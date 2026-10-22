from __future__ import annotations

import base64
import copy
import gzip
import hashlib
import json
import re
import unittest
from datetime import datetime, timezone
from pathlib import Path

from jsonschema import Draft4Validator, ValidationError
from openapi_spec_validator import OpenAPIV2SpecValidator

from tests.wdl_local import Expression, LocalWorkflow, check_parse_json_schema, stringify
from tools import build_template as build

ROOT = Path(__file__).resolve().parent.parent


def visit(actions, depth=1):
    for name, action in actions.items():
        yield name, action, depth
        children = [action.get("actions", {}), action.get("else", {}).get("actions", {})]
        children += [case.get("actions", {}) for case in action.get("cases", {}).values()]
        children += [action.get("default", {}).get("actions", {})]
        for child in children:
            yield from visit(child, depth + 1)


def strings(value):
    if isinstance(value, str):
        yield value
    elif isinstance(value, dict):
        for item in value.values(): yield from strings(item)
    elif isinstance(value, list):
        for item in value: yield from strings(item)


def sample_cve():
    return {
        "id": "CVE-2026-12345", "published": "2026-10-19T00:00:00.000",
        "descriptions": [{"lang": "en", "value": "Full source text.\r\nPreserve this line."}],
        "metrics": {"cvssMetricV31": [{
            "source": "synthetic@example.invalid", "type": "Secondary",
            "cvssData": {"version": "3.1", "baseScore": 9.8, "baseSeverity": "CRITICAL"},
        }]},
    }


class NativeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.spec = json.loads((ROOT / "NvdCveApi.swagger.json").read_text(encoding="utf-8"))
        cls.template = build.build()
        cls.formatter = build.formatter_definition(cls.spec)
        cls.worker = build.worker_definition(cls.spec)

    def format(self, cves, day="2026-10-19", total=None):
        engine = LocalWorkflow(trigger={
            "ReportDate": day, "PublishedCount": len(cves) if total is None else total,
            "CollectedAt": "2026-10-21T03:00:00Z", "Cves": cves,
        })
        response = engine.run(self.formatter["actions"])
        self.assertEqual(response["statusCode"], 200)
        return response["body"]

    def test_generated_template_matches_authoring_source(self):
        actual = json.loads((ROOT / "azuredeploy.json").read_text(encoding="utf-8"))
        self.assertEqual(actual, self.template)

    def test_parse_json_schemas_exclude_native_unsupported_keywords(self):
        checked = 0
        for resource in self.template["resources"]:
            if resource["type"] != "Microsoft.Logic/workflows":
                continue
            for name, action, depth in visit(resource["properties"]["definition"]["actions"]):
                if action["type"] == "ParseJson":
                    check_parse_json_schema(action["inputs"]["schema"])
                    checked += 1
        self.assertGreater(checked, 10)
        self.assertIn("pattern", self.spec["definitions"]["Cve"]["properties"]["id"])

    def test_local_engine_rejects_the_actual_azure_schema_failure(self):
        for schema in (
            {"type": "string", "pattern": "^x$"},
            {"type": "object", "patternProperties": {"^x": {"type": "string"}}},
            {"type": "object", "definitions": {"nested": {"pattern": "^x$"}}},
        ):
            with self.subTest(schema=schema):
                with self.assertRaisesRegex(ValueError, "Unsupported native ParseJson"):
                    LocalWorkflow().execute("Regression", {
                        "type": "ParseJson", "inputs": {"content": "x", "schema": schema},
                    })

    def test_native_cve_id_validation_does_not_depend_on_regex_schema(self):
        for identifier in ("CVE-2026-1234", "CVE-2026-123456789"):
            cve = sample_cve()
            cve["id"] = identifier
            self.assertEqual(self.format([cve])["CriticalCount"], 1)
        for identifier in ("CVE-26-1234", "CVE-20X6-1234", "cve-2026-1234",
                           "CVE-2026-1234x", "CVE-2026-１２３４", "CVE-20261-1234"):
            cve = sample_cve()
            cve["id"] = identifier
            with self.subTest(identifier=identifier):
                with self.assertRaises((ValidationError, ValueError)):
                    self.format([cve])

    def test_native_mail_configuration_rejects_invalid_addresses(self):
        for sender in ("admin@example.com", "valid+tag@example.invalid"):
            LocalWorkflow(parameters={
                "SenderMailbox": sender, "RecipientEmail": "recipient@example.invalid",
            }).run(build.mail_configuration_validation())
        for address in ("", "a@example", "a@@example.invalid", "a@example.",
                        "a b@example.invalid", "a\tb@example.invalid",
                        "a\u00a0b@example.invalid", "a@example.invalid\n",
                        "a@example.invalid;b@example.invalid", "<a@example.invalid>"):
            for field in ("SenderMailbox", "RecipientEmail"):
                parameters = {"SenderMailbox": "sender@example.invalid", "RecipientEmail": "recipient@example.invalid"}
                parameters[field] = address
                with self.subTest(field=field, address=address):
                    with self.assertRaises((ValidationError, ValueError)):
                        LocalWorkflow(parameters=parameters).run(build.mail_configuration_validation())

    def test_native_report_date_validation_rejects_invalid_or_disallowed_days(self):
        action = self.worker["actions"]["Prepare_This_Run"]["actions"]["Prepare_Try"]["actions"]["Validate_Report_Date"]
        for day in ("2026-10-19", "2026-10-21", "2026-02-30", "2026/10/20"):
            engine = LocalWorkflow(variables={"ReportDate": day}, parameters={"FirstReportDate": "2026-10-20"})
            engine.outputs["Current_Due_Date"] = "2026-10-20"
            with self.subTest(day=day):
                with self.assertRaises((ValidationError, ValueError)):
                    engine.execute("Validate_Report_Date", action)
        with self.assertRaises((ValidationError, ValueError)):
            self.format([], day="2026/10/20")

    def test_retry_after_requires_one_to_six_ascii_digits_without_regex(self):
        actions = {name: action for name, action, depth in visit(self.worker["actions"])}
        for text in ("1", "000001", "999999", "", "+1", "-1", "1.0", " 1", "1\n", "١", "1000000"):
            engine = LocalWorkflow()
            engine.outputs["Retry_After_Seconds"] = text
            def validate():
                for name in ("Validate_Retry_After", "Validate_Retry_After_Digits"):
                    engine.execute(name, actions[name])
            with self.subTest(text=text):
                if re.fullmatch(r"[0-9]{1,6}", text):
                    validate()
                else:
                    with self.assertRaises((ValidationError, ValueError)):
                        validate()

    def test_openapi_is_valid_and_has_no_unsafe_server_severity_filter(self):
        OpenAPIV2SpecValidator(self.spec).validate()
        operation = self.spec["paths"]["/rest/json/cves/2.0"]["get"]
        self.assertEqual({entry["name"] for entry in operation["parameters"] if entry["in"] == "query"}, {
            "pubStartDate", "pubEndDate", "startIndex", "resultsPerPage",
        })
        self.assertEqual(self.spec["host"], "services.nvd.nist.gov")
        self.assertEqual(self.spec["security"], [])
        self.assertNotIn("securityDefinitions", self.spec)

    def test_nvd_key_is_a_secure_workflow_parameter_and_protected_header(self):
        self.assertEqual(self.worker["parameters"]["NvdApiKey"], {"type": "SecureString"})
        worker = next(resource for resource in self.template["resources"]
                      if resource["type"] == "Microsoft.Logic/workflows" and resource["name"] == "[variables('workerName')]")
        self.assertEqual(worker["properties"]["parameters"]["NvdApiKey"], {"value": "[parameters('nvdApiKey')]"})
        read = next(action for name, action, depth in visit(self.worker["actions"]) if name == "Read_NVD_Page")
        self.assertEqual(read["inputs"]["headers"]["apiKey"], "@parameters('NvdApiKey')")
        self.assertEqual(set(read["runtimeConfiguration"]["secureData"]["properties"]), {"inputs", "outputs"})
        connector = next(resource for resource in self.template["resources"] if resource["type"] == "Microsoft.Web/customApis")
        connection = next(resource for resource in self.template["resources"] if resource["type"] == "Microsoft.Web/connections")
        self.assertNotIn("connectionParameters", connector["properties"])
        self.assertNotIn("parameterValues", connection["properties"])
        example = json.loads((ROOT / "azuredeploy.parameters.example.json").read_text(encoding="utf-8"))
        self.assertNotIn("reference", example["parameters"]["nvdApiKey"])

    def test_unset_or_invalid_keys_fail_without_logging_secret_inputs(self):
        guard = build.source_preparation(self.spec)["Validate_NVD_Key"]["inputs"]["content"]
        for key in ("", "<YOUR-NVD-API-KEY>", "synthetic-key-value\n", "synthetic key value"):
            with self.subTest(key=key):
                self.assertFalse(LocalWorkflow(parameters={"NvdApiKey": key}).resolve(guard))
        self.assertTrue(LocalWorkflow(parameters={"NvdApiKey": "synthetic-nvd-key-123456"}).resolve(guard))
        for text in strings(self.worker["actions"]):
            self.assertNotIn("string(result(", text)
        for name, action, depth in visit(self.worker["actions"]):
            if name.endswith(("_Failed_Actions", "_Failure_Summary")):
                self.assertEqual(set(action["runtimeConfiguration"]["secureData"]["properties"]), {"inputs", "outputs"})

    def test_only_native_consumption_resources_and_safe_defaults(self):
        resources = self.template["resources"]
        self.assertEqual(sum(item["type"] == "Microsoft.Logic/workflows" for item in resources), 3)
        self.assertFalse(any(item["type"] in {"Microsoft.Web/sites", "Microsoft.Logic/integrationAccounts"} for item in resources))
        self.assertEqual(self.template["parameters"]["scheduleState"]["defaultValue"], "Disabled")
        self.assertFalse(self.template["parameters"]["mailSendingEnabled"]["defaultValue"])
        self.assertEqual(self.template["parameters"]["nvdApiKey"]["type"], "securestring")
        self.assertNotIn("defaultValue", self.template["parameters"]["nvdApiKey"])
        self.assertFalse(any(item["type"].startswith("Microsoft.Storage/") for item in resources))
        self.assertFalse(any(item["type"] == "Microsoft.Authorization/roleAssignments" for item in resources))

    def test_no_customer_storage_parameters_or_calls(self):
        for key in ("TableEndpoint", "BlobEndpoint", "ReportContainer"):
            self.assertNotIn(key, self.worker["parameters"])
        encoded = json.dumps(self.worker["actions"])
        self.assertNotIn("storage.azure.com", encoded)
        self.assertNotIn("DailyReports", encoded)
        self.assertNotIn("ControlState", encoded)
        wrapper = (ROOT / "infra" / "main.bicep").read_text(encoding="utf-8")
        self.assertNotIn("storagePublicNetworkAccess", wrapper)

    def test_request_triggered_workflows_accept_only_other_logic_apps(self):
        resources = {item["name"]: item for item in self.template["resources"] if item["type"] == "Microsoft.Logic/workflows"}
        only_logic_apps = {"triggers": {"allowedCallerIpAddresses": [{"addressRange": "0.0.0.0-0.0.0.0"}]}}
        for key in ("[variables('workerName')]", "[variables('formatterName')]"):
            self.assertEqual(resources[key]["properties"]["accessControl"], only_logic_apps)
        self.assertNotIn("accessControl", resources["[variables('schedulerName')]"]["properties"])

    def test_portal_editable_parameters_use_defaults_not_stale_outer_values(self):
        resources = {item["name"]: item for item in self.template["resources"] if item["type"] == "Microsoft.Logic/workflows"}
        worker = resources["[variables('workerName')]"]["properties"]
        scheduler = resources["[variables('schedulerName')]"]["properties"]
        expected = {
            "SenderMailbox": "senderMailbox", "RecipientEmail": "recipientEmail",
            "FirstReportDate": "firstReportDate", "MailSendingEnabled": "mailSendingEnabled",
            "MaxMailRequestBytes": "maxMailRequestBytes", "NvdPageSize": "nvdPageSize",
        }
        for name, template_parameter in expected.items():
            self.assertEqual(worker["definition"]["parameters"][name]["defaultValue"], f"[parameters('{template_parameter}')]")
            self.assertNotIn(name, worker["parameters"])
        self.assertEqual(set(worker["parameters"]), {"$connections", "NvdApiKey"})
        self.assertNotIn("defaultValue", worker["definition"]["parameters"]["NvdApiKey"])
        self.assertEqual(scheduler["definition"]["parameters"]["FirstReportDate"]["defaultValue"], "[parameters('firstReportDate')]")
        self.assertEqual(scheduler["parameters"], {})

    def test_audit_reports_non_secret_effective_mail_and_key_state(self):
        audit = next(action for name, action, depth in visit(self.worker["actions"]) if name == "Record_Audit_Event")
        self.assertIn("MailSendingEnabled", audit["trackedProperties"])
        self.assertIn("NvdKeyConfigured", audit["trackedProperties"])
        expression = audit["inputs"]["NvdKeyConfigured"]
        for key, expected in (("", False), ("<NOT-CONFIGURED>", False), ("synthetic-nvd-key-123456", True)):
            with self.subTest(key=key):
                self.assertIs(LocalWorkflow(parameters={"NvdApiKey": key}).resolve(expression), expected)
        self.assertNotIn("NvdApiKey", json.dumps(audit["trackedProperties"]))

    def test_actions_references_nesting_and_variable_updates(self):
        for resource in self.template["resources"]:
            if resource["type"] != "Microsoft.Logic/workflows": continue
            definition = resource["properties"]["definition"]
            actions = list(visit(definition["actions"]))
            names = {name for name, action, depth in actions}
            self.assertEqual(len(names), len(actions))
            self.assertLessEqual(len(actions), 500)
            self.assertLessEqual(max(depth for name, action, depth in actions), 8)
            variables = {
                variable["name"] for name, action, depth in actions if action["type"] == "InitializeVariable"
                for variable in action["inputs"]["variables"]
            }
            for name, action, depth in actions:
                if action["type"] == "SetVariable":
                    value = json.dumps(action["inputs"]["value"])
                    self.assertNotIn(f"variables('{action['inputs']['name']}')", value, name)
                if action["type"] == "Foreach":
                    self.assertEqual(action["runtimeConfiguration"]["concurrency"]["repetitions"], 1)
                if action["type"] == "Until":
                    self.assertEqual(action["operationOptions"], "FailWhenLimitsReached")
                self.assertNotIn(action["type"], {"JavaScriptCode", "Function", "InlineCode"})
                for text in strings(action):
                    if not text.startswith("@") or text.startswith("@@"): continue
                    Expression(text[1:]).parse()
                    for kind, target in re.findall(r"(outputs|body|actions|result|items)\('([^']+)'\)", text):
                        self.assertIn(target, names, (name, kind, target))
                    for target in re.findall(r"variables\('([^']+)'\)", text):
                        self.assertIn(target, variables, (name, target))
                    for target in re.findall(r"parameters\('([^']+)'\)", text):
                        self.assertIn(target, definition["parameters"], (name, target))

    def test_schedule_is_local_jst_not_0900_utc(self):
        scheduler = build.scheduler_definition()
        trigger = scheduler["triggers"]["Daily_0900_JST"]
        self.assertEqual(trigger["recurrence"]["timeZone"], "Tokyo Standard Time")
        self.assertEqual(trigger["recurrence"]["schedule"], {"hours": [9], "minutes": [0]})
        self.assertEqual(trigger["recurrence"]["startTime"], "[parameters('firstScheduleLocalTime')]")
        default = self.template["parameters"]["firstScheduleLocalTime"]["defaultValue"]
        self.assertTrue(default.endswith("'T08:00:00')]"), "start must precede 09:00 or the first 09:00 run is skipped")
        engine = LocalWorkflow()
        engine.clock = datetime(2026, 10, 20, 23, 59, tzinfo=timezone.utc)
        self.assertEqual(engine.resolve(build.DUE_DATE), "2026-10-19")
        engine.clock = datetime(2026, 10, 21, 0, 0, tzinfo=timezone.utc)
        self.assertEqual(engine.resolve(build.DUE_DATE), "2026-10-20")

    def test_sync_request_children_do_not_use_unsupported_trigger_concurrency(self):
        for definition in (self.worker, self.formatter):
            self.assertNotIn("runtimeConfiguration", definition["triggers"]["manual"])
        scheduler = build.scheduler_definition()
        self.assertEqual(scheduler["triggers"]["Daily_0900_JST"]["runtimeConfiguration"]["concurrency"]["runs"], 1)

    def test_designer_required_values_are_never_empty_literals(self):
        for resource in self.template["resources"]:
            if resource["type"] != "Microsoft.Logic/workflows":
                continue
            for name, action, depth in visit(resource["properties"]["definition"]["actions"]):
                if action["type"] == "SetVariable":
                    self.assertNotEqual(action["inputs"]["value"], "", name)
        actions = {name: action for name, action, depth in visit(self.worker["actions"])}
        engine = LocalWorkflow()
        for name in ("Clear_Accepted_Error", "Clear_Accepted_Reason"):
            engine.execute(name, actions[name])
            self.assertEqual(engine.variables[actions[name]["inputs"]["name"]], "")

    def test_publication_window_keeps_the_last_millisecond(self):
        engine = LocalWorkflow(variables={"ReportDate": "2026-10-19"})
        source = build.source_preparation(self.spec)
        for name in ("Publication_Start_UTC", "Publication_Next_Midnight_UTC", "Publication_End_UTC"):
            engine.execute(name, source[name])
        self.assertEqual(engine.outputs["Publication_Start_UTC"], "2026-10-18T15:00:00.000Z")
        self.assertEqual(engine.outputs["Publication_End_UTC"], "2026-10-19T14:59:59.999Z")

    def test_formatter_preserves_full_text_and_missing_values(self):
        cve = sample_cve()
        result = self.format([cve])
        body = result["ReportBody"]
        self.assertEqual(result["CriticalCount"], 1)
        self.assertFalse(result["LLMUsed"])
        self.assertIn(cve["descriptions"][0]["value"], body)
        self.assertIn("9.8; baseSeverity: CRITICAL", body)
        self.assertIn("CVSS 4.0 assessments:\n  baseScore: Not provided by NVD", body)

    def test_zero_cves_is_a_completed_zero_report(self):
        result = self.format([], total=12)
        self.assertIn("Daily vulnerability count (distinct CVEs): 0", result["ReportBody"])
        self.assertIn("All published CVEs inspected: 12", result["ReportBody"])
        self.assertIn("No CVEs matched", result["ReportBody"])

    def test_native_cpe_escaping_matches_independent_parser(self):
        samples = [
            ("cpe:2.3:a:example:product:1.0:*:*:*:*:*:*:*", "example", "product", "1.0"),
            (r"cpe:2.3:a:vendor\:name:product\\team:*:*:*:*:*:*:*:*", r"vendor\:name", r"product\\team", "*"),
            (r"cpe:2.3:a:vendor%3Aname:product%5Cname:1.0\:\*:*:*:*:*:*:*:*", "vendor%3Aname", "product%5Cname", r"1.0\:\*"),
            (r"cpe:2.3:a:vendor\\\:name:product:*:*:*:*:*:*:*:*", r"vendor\\\:name", "product", "*"),
        ]
        for criteria, vendor, product, version in samples:
            with self.subTest(criteria=criteria):
                cve = sample_cve()
                cve["configurations"] = [{
                    "operator": "AND", "negate": True, "children": [{
                        "operator": "OR", "cpeMatch": [{
                            "vulnerable": True, "criteria": criteria,
                            "versionStartIncluding": "1.0", "versionEndExcluding": "2.0",
                        }, {
                            "vulnerable": False, "criteria": "cpe:2.3:o:example:os:11:*:*:*:*:*:*:*",
                        }],
                    }],
                }]
                body = self.format([cve])["ReportBody"]
                self.assertIn(f"Vendor: {vendor} / Product: {product} / Version: {version}", body)
                self.assertIn("versionStartIncluding: 1.0", body)
                self.assertIn("versionEndExcluding: 2.0", body)
                self.assertIn(stringify(cve["configurations"]), body)

    def test_malformed_cpe_and_cvss_cannot_generate_partial_success(self):
        cve = sample_cve()
        cve["configurations"] = [{"cpeMatch": [{"vulnerable": True, "criteria": "invalid"}]}]
        with self.assertRaises(ValidationError):
            self.format([cve])
        cve = sample_cve()
        cve["metrics"]["cvssMetricV31"][0]["cvssData"]["baseScore"] = 8.9
        with self.assertRaises(ValidationError):
            self.format([cve])

    def select(self, cves):
        source = build.source_preparation(self.spec)
        actions = {name: copy.deepcopy(source[name]) for name in ("Candidate_Critical_CVEs", "Check_All_CVEs")}
        for action in actions.values():
            action["runAfter"] = {}
        engine = LocalWorkflow(variables={"CurrentCves": cves, "CriticalCves": []})
        engine.run(actions)
        return engine

    def test_selection_is_any_source_or_and_excludes_v30(self):
        records = [sample_cve(), sample_cve(), sample_cve(), sample_cve(), sample_cve()]
        for index, cve in enumerate(records): cve["id"] = f"CVE-2026-{10000 + index}"
        records[1]["metrics"] = {"cvssMetricV30": [{
            "cvssData": {"version": "3.0", "baseScore": 9.8, "baseSeverity": "CRITICAL"},
        }]}
        records[2]["metrics"]["cvssMetricV40"] = [{
            "cvssData": {"version": "4.0", "baseScore": 10, "baseSeverity": "CRITICAL"},
        }]
        records[3]["metrics"] = {}
        records[4].pop("metrics")
        engine = self.select(records)
        self.assertEqual([item["id"] for item in engine.variables["CriticalCves"]], [
            "CVE-2026-10000", "CVE-2026-10002",
        ])
        candidates = [item["id"] for item in engine.outputs["Candidate_Critical_CVEs"]["body"]]
        self.assertEqual(candidates, ["CVE-2026-10000", "CVE-2026-10001", "CVE-2026-10002"])

    def test_candidate_prefilter_is_a_superset_that_never_hides_a_critical_cve(self):
        records = [sample_cve() for _ in range(4)]
        for index, cve in enumerate(records): cve["id"] = f"CVE-2026-{20000 + index}"
        records[0]["metrics"] = {"cvssMetricV31": [
            {"cvssData": {"version": "3.1", "baseScore": 5.0, "baseSeverity": "MEDIUM"}},
            {"cvssData": {"version": "3.1", "baseScore": 9.9, "baseSeverity": "CRITICAL"}},
        ]}
        records[1]["metrics"] = {"cvssMetricV40": [{"cvssData": {"version": "4.0", "baseScore": 9.5, "baseSeverity": "CRITICAL"}}]}
        records[2]["metrics"] = {"cvssMetricV31": [{"cvssData": {"version": "3.1", "baseScore": 8.9, "baseSeverity": "HIGH"}}]}
        records[3]["metrics"] = {"cvssMetricV2": [{"baseSeverity": "HIGH", "cvssData": {"version": "2.0", "baseScore": 7.5}}]}
        engine = self.select(records)
        selected = {item["id"] for item in engine.variables["CriticalCves"]}
        candidates = {item["id"] for item in engine.outputs["Candidate_Critical_CVEs"]["body"]}
        self.assertEqual(selected, {"CVE-2026-20000", "CVE-2026-20001"})
        self.assertTrue(selected <= candidates)
        self.assertEqual(candidates, selected)

    def test_mail_request_is_an_office365_connector_call_with_exact_size_gate(self):
        for text in ("ASCII", "日本語 😀\r\n\"\\"):
            request = json.dumps({"To": "a@example.invalid", "Subject": "s", "Body": text}, ensure_ascii=False)
            encoded = base64.b64encode(request.encode("utf-8")).decode("ascii")
            engine = LocalWorkflow(variables={"RequestBase64": encoded})
            expression = build.source_preparation(self.spec)["Exact_Request_Bytes"]["inputs"]
            self.assertEqual(engine.resolve(expression), len(request.encode("utf-8")))
        send = next(action for name, action, depth in visit(self.worker["actions"]) if name == "Send_Office365_Mail")
        self.assertEqual(send["type"], "ApiConnection")
        self.assertEqual(send["inputs"]["method"], "post")
        self.assertEqual(send["inputs"]["path"], "/v2/Mail")
        self.assertEqual(send["inputs"]["host"]["connection"]["name"], "@parameters('$connections')['office365']['connectionId']")
        self.assertEqual(send["inputs"]["body"], "@outputs('Mail_Request_Object')")
        self.assertEqual(send["inputs"]["retryPolicy"], {"type": "none"})
        self.assertEqual(send["runtimeConfiguration"]["secureData"]["properties"], ["inputs"])
        encoded_worker = json.dumps(self.worker)
        for forbidden in ("graph.microsoft.com", "ManagedServiceIdentity", "sendMail"):
            self.assertNotIn(forbidden, encoded_worker)

    def test_html_body_escapes_untrusted_cve_text_and_preserves_layout(self):
        source = build.source_preparation(self.spec)
        body = "CVE-2026-1\r\n<script>alert(\"x\")</script> & 'quote' > tail\n  indented"
        engine = LocalWorkflow(variables={"ReportBody": body})
        engine.execute("Mail_Body_Html", source["Mail_Body_Html"])
        html = engine.outputs["Mail_Body_Html"]
        self.assertTrue(html.startswith('<pre style="') and html.endswith("</pre>"))
        inner = html.split('">', 1)[1][: -len("</pre>")]
        self.assertNotIn("<", inner)
        self.assertNotIn(">", inner)
        self.assertNotIn('"', inner)
        self.assertEqual(inner.replace("&quot;", '"').replace("&gt;", ">").replace("&lt;", "<").replace("&amp;", "&"), body)
        self.assertIn("white-space:pre-wrap", html)

    def test_office365_connection_is_conditional_and_wired_to_the_worker(self):
        connection = next(item for item in self.template["resources"] if item["name"] == "[variables('office365ConnectionName')]")
        self.assertEqual(connection["type"], "Microsoft.Web/connections")
        self.assertEqual(connection["condition"], "[parameters('createOffice365Connection')]")
        managed_api = "[subscriptionResourceId('Microsoft.Web/locations/managedApis', parameters('location'), 'office365')]"
        self.assertEqual(connection["properties"]["api"]["id"], managed_api)
        self.assertTrue(self.template["parameters"]["createOffice365Connection"]["defaultValue"])
        worker = next(item for item in self.template["resources"] if item["name"] == "[variables('workerName')]")
        entry = worker["properties"]["parameters"]["$connections"]["value"]["office365"]
        self.assertEqual(entry["id"], managed_api)
        self.assertIn("[resourceId('Microsoft.Web/connections', variables('office365ConnectionName'))]", worker["dependsOn"])
        self.assertNotIn("connectionParameters", json.dumps(connection))

    def test_one_byte_over_budget_is_not_sent(self):
        gate = next(action for name, action, depth in visit(self.worker["actions"]) if name == "If_One_Mail_Fits")
        engine = LocalWorkflow(parameters={"MaxMailRequestBytes": 1024}, variables={"RequestBytes": 1024})
        self.assertTrue(engine.resolve(gate["expression"]))
        engine.variables["RequestBytes"] = 1025
        self.assertFalse(engine.resolve(gate["expression"]))

    def test_mail_response_classification_does_not_retry_ambiguous_results(self):
        expression = next(action for name, action, depth in visit(self.worker["actions"]) if name == "Mail_Response_Class")["inputs"]
        for code, expected in (
            (200, "accepted"), (202, "accepted"), (429, "retry"), (400, "rejected"), (403, "rejected"),
            (413, "rejected"), (408, "uncertain"), (500, "uncertain"), (503, "uncertain"), (0, "uncertain"),
        ):
            with self.subTest(code=code):
                engine = LocalWorkflow(variables={"MailHttpStatus": code})
                engine.status["Send_Office365_Mail"] = "Succeeded" if code in (200, 202) else "Failed"
                self.assertEqual(engine.resolve(expression), expected)
        engine = LocalWorkflow(variables={"MailHttpStatus": 0})
        engine.status["Send_Office365_Mail"] = "Skipped"
        self.assertEqual(engine.resolve(expression), "uncertain")

    def test_history_audit_and_diagnostic_routes(self):
        roles = [item for item in self.template["resources"] if item["type"] == "Microsoft.Authorization/roleAssignments"]
        self.assertEqual(roles, [])
        names = {name: action for name, action, depth in visit(self.worker["actions"])}
        self.assertEqual(names["Send_Office365_Mail"]["runAfter"], {"Record_Submission_Attempt": ["Succeeded"]})
        self.assertIn("Record_Complete_Source", names)
        self.assertIn("Record_TEXT_Report", names)
        self.assertIn("Record_Audit_Event", names)
        audit = names["Record_Audit_Event"]
        self.assertFalse(audit["inputs"]["CrossRunDuplicateProtection"])
        self.assertIn("ErrorReason", audit["trackedProperties"])
        for value in audit["trackedProperties"].values():
            self.assertTrue(value.startswith("@action()"))
            self.assertNotIn("NvdApiKey", value)
        diagnostics = [item for item in self.template["resources"] if item["type"] == "Microsoft.Insights/diagnosticSettings"]
        self.assertEqual(len(diagnostics), 3)
        for diagnostic in diagnostics:
            self.assertEqual(diagnostic["properties"]["workspaceId"], "[parameters('logAnalyticsWorkspaceId')]")
            self.assertEqual(diagnostic["properties"]["logs"], [{"category": "WorkflowRuntime", "enabled": True}])

    def test_scheduler_has_no_persistent_cursor_or_automatic_replay(self):
        definition = build.scheduler_definition()
        names = {name for name, action, depth in visit(definition["actions"])}
        self.assertNotIn("Catch_Up_Due_Days", names)
        self.assertNotIn("Query_Control_Cursor", names)
        self.assertEqual(sum(action["type"] == "Workflow" for name, action, depth in visit(definition["actions"])), 1)
        for name, action, depth in visit(definition["actions"]):
            if action["type"] == "Workflow":
                self.assertEqual(action["inputs"]["retryPolicy"], {"type": "none"})

    def test_report_bytes_match_the_pre_optimization_baseline(self):
        data = ROOT.parent / "NvdWeeklyAssessment_20261021" / "data"
        if not data.is_dir():
            self.skipTest("The sibling weekly study's archived NVD data is not present.")
        baseline = json.loads((ROOT / "tests" / "replay_baseline.json").read_text(encoding="utf-8"))["days"]
        self.assertEqual(len(baseline), 7)
        for day, expected in baseline.items():
            with self.subTest(day=day):
                with gzip.open(data / day / "snapshot.json.gz", "rt", encoding="utf-8") as source:
                    saved = json.load(source)
                self.assertEqual(len(saved["cves"]), expected["published"])
                selected = self.select(saved["cves"]).variables["CriticalCves"]
                text = self.format(selected, day, len(saved["cves"]))["ReportBody"]
                separator = re.compile(r"(?m)^(\d{4}-\d{2}-\d{2}) #(\d+) (CVE-\d{4}-\d{4,}) -{72}$\n(CVE: (\S+))$")
                found = separator.findall(text)
                self.assertEqual(len(found), len(selected))
                for index, (date, number, separator_id, _, cve_line_id) in enumerate(found, start=1):
                    self.assertEqual((date, int(number)), (day, index))
                    self.assertEqual(separator_id, cve_line_id)
                self.assertEqual([item[2] for item in found], sorted(item["id"] for item in selected))
                # Only the CVE separator lines changed; restoring them reproduces the original bytes exactly.
                legacy = re.sub(r"(?m)^\d{4}-\d{2}-\d{2} #\d+ CVE-\d{4}-\d{4,} -{72}$", "=" * 72, text)
                encoded = legacy.encode("utf-8")
                self.assertEqual(len(encoded), expected["body_bytes"])
                self.assertEqual(hashlib.sha256(encoded).hexdigest(), expected["body_sha256"])

    def test_formatter_uses_batch_actions_instead_of_per_item_loops(self):
        actions = {name: action for name, action, depth in visit(self.formatter["actions"])}
        self.assertEqual({name for name, action in actions.items() if action["type"] == "Foreach"},
                         {"For_each_CVE", "For_each_Node", "For_each_Child"})
        for name in ("Description_Lines", "Metric40_Lines", "Metric31_Lines", "CPE_Parts", "CPE_Lines"):
            self.assertEqual(actions[name]["type"], "Select", name)
        source = {name: action for name, action, depth in visit(build.source_preparation(self.spec))}
        self.assertEqual(source["Candidate_Critical_CVEs"]["type"], "Query")
        self.assertEqual(source["Check_All_CVEs"]["foreach"], "@sort(body('Candidate_Critical_CVEs'), 'id')")

    def test_replay_all_captured_weekly_cves_without_network(self):
        data = ROOT.parent / "NvdWeeklyAssessment_20261021" / "data"
        if not data.is_dir():
            self.skipTest("The sibling weekly study's archived NVD data is not present.")
        expected = {
            "2026-10-14": 157, "2026-10-15": 96, "2026-10-16": 46, "2026-10-17": 40,
            "2026-10-18": 6, "2026-10-19": 11, "2026-10-20": 37,
        }
        total = 0
        for day, count in expected.items():
            with self.subTest(day=day):
                with gzip.open(data / day / "snapshot.json.gz", "rt", encoding="utf-8") as source:
                    saved = json.load(source)
                engine = self.select(saved["cves"])
                selected = engine.variables["CriticalCves"]
                candidates = engine.outputs["Candidate_Critical_CVEs"]["body"]
                self.assertTrue({item["id"] for item in selected} <= {item["id"] for item in candidates})
                self.assertLess(len(candidates), len(saved["cves"]) // 2 + 20)
                self.assertEqual(len(selected), count)
                result = self.format(selected, day, len(saved["cves"]))
                self.assertEqual(result["CriticalCount"], count)
                body = result["ReportBody"]
                for cve in selected:
                    self.assertIn(f"CVE: {cve['id']}", body)
                    section = body.split(f"\nCVE: {cve['id']}\n", 1)[1]
                    section = re.split(r"\n\d{4}-\d{2}-\d{2} #\d+ CVE-\d{4}-\d{4,} -{72}\n", section, maxsplit=1)[0]
                    for description in cve.get("descriptions", []):
                        self.assertIn(description["value"], section)
                    for key in ("cvssMetricV40", "cvssMetricV31"):
                        for metric in cve.get("metrics", {}).get(key, []):
                            metric_data = metric["cvssData"]
                            self.assertIn(
                                f"baseScore: {stringify(metric_data['baseScore'])}; baseSeverity: {metric_data['baseSeverity']}",
                                section,
                            )
                    self.assertIn(stringify(cve.get("configurations", [])), section)
                    self.assertIn(stringify(cve.get("affected", [])), section)
                total += count
        self.assertEqual(total, 393)


if __name__ == "__main__":
    unittest.main()
