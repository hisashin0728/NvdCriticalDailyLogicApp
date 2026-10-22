"""Build deployment JSON. This authoring tool is NOT deployed or used at runtime."""

from __future__ import annotations

import copy
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
WF_SCHEMA = "https://schema.management.azure.com/providers/Microsoft.Logic/schemas/2016-06-01/workflowdefinition.json#"
ALL = ["Succeeded", "Failed", "TimedOut", "Skipped"]
FAILED = ["Failed", "TimedOut"]
LF = "decodeUriComponent('%0A')"
DUE_DATE = (
    "@formatDateTime(addDays(convertFromUtc(utcNow(), 'Tokyo Standard Time'), "
    "if(greaterOrEquals(int(formatDateTime(convertFromUtc(utcNow(), 'Tokyo Standard Time'), 'HH')), "
    "9), -1, -2)), 'yyyy-MM-dd')"
)


MAIL_BODY_HTML = (
    "@concat('<pre style=\"font-family:Consolas,Menlo,monospace;font-size:12px;"
    "white-space:pre-wrap;word-wrap:break-word\">', "
    "replace(replace(replace(replace(variables('ReportBody'), '&', '&amp;'), '<', '&lt;'), '>', '&gt;'), "
    "'\"', '&quot;'), '</pre>')"
)


def sequence(*entries: tuple[str, dict]) -> dict:
    result = {}
    previous = None
    for name, action in entries:
        if name in result:
            raise ValueError(f"Duplicate sibling action: {name}")
        action = copy.deepcopy(action)
        if "runAfter" not in action:
            action["runAfter"] = {previous: ["Succeeded"]} if previous else {}
        result[name] = action
        previous = name
    return result


def compose(value) -> dict:
    return {"type": "Compose", "inputs": value}


def setvar(name: str, value) -> dict:
    return {"type": "SetVariable", "inputs": {"name": name, "value": value}}


def append(name: str, value, array: bool = False) -> dict:
    return {
        "type": "AppendToArrayVariable" if array else "AppendToStringVariable",
        "inputs": {"name": name, "value": value},
    }


def initialize(values: dict[str, tuple[str, object]]) -> list[tuple[str, dict]]:
    return [
        (f"Initialize_{name}", {
            "type": "InitializeVariable",
            "inputs": {"variables": [{"name": name, "type": kind, "value": value}]},
        })
        for name, (kind, value) in values.items()
    ]


def condition(expression: str, yes: dict, no: dict | None = None) -> dict:
    return {"type": "If", "expression": expression, "actions": yes, "else": {"actions": no or {}}}


def foreach(source: str, actions: dict) -> dict:
    return {
        "type": "Foreach", "foreach": source, "actions": actions,
        "runtimeConfiguration": {"concurrency": {"repetitions": 1}},
    }


def until(expression: str, actions: dict, count: int = 5000, timeout: str = "PT6H") -> dict:
    return {
        "type": "Until", "expression": expression, "actions": actions,
        "limit": {"count": count, "timeout": timeout},
        "operationOptions": "FailWhenLimitsReached",
    }


def scope(actions: dict, after: dict | None = None) -> dict:
    result = {"type": "Scope", "actions": actions}
    if after is not None:
        result["runAfter"] = after
    return result


def assertion(expression: str) -> dict:
    return {
        "type": "ParseJson",
        "inputs": {"content": expression, "schema": {"type": "boolean", "enum": [True]}},
    }


def digits_only(value: str) -> str:
    remainder = value
    for digit in "0123456789":
        remainder = f"replace({remainder}, '{digit}', '')"
    return f"and(greater(length({value}), 0), equals({remainder}, ''))"


def valid_cve_id(value: str) -> str:
    return (
        f"and(startsWith({value}, 'CVE-'), equals(substring({value}, 8, 1), '-'), "
        f"{digits_only(f'substring({value}, 4, 4)')}, "
        f"{digits_only(f'substring({value}, 9)')})"
    )


def cve_ids_validation(source: str, value: str) -> dict:
    checks = sequence(
        ("Find_Invalid_CVE_Ids", {
            "type": "Query",
            "inputs": {"from": source, "where": f"@not({valid_cve_id(value)})"},
        }),
        ("Validate_CVE_Ids", assertion("@empty(body('Find_Invalid_CVE_Ids'))")),
    )
    del checks["Find_Invalid_CVE_Ids"]["runAfter"]
    return checks


def mail_configuration_validation() -> dict:
    forbidden = [
        *map(chr, range(9, 14)), *map(chr, range(28, 33)),
        "\u0085", "\u00a0", "\u1680", *map(chr, range(0x2000, 0x200B)),
        "\u2028", "\u2029", "\u202f", "\u205f", "\u3000", ",", ";", "<", ">",
    ]
    shapes = []
    for parameter in ("SenderMailbox", "RecipientEmail"):
        address = f"parameters('{parameter}')"
        domain = f"last(split({address}, '@'))"
        shapes.append(
            f"and(equals(length(split({address}, '@')), 2), "
            f"not(empty(first(split({address}, '@')))), contains({domain}, '.'), "
            f"not(empty(first(split({domain}, '.')))), not(empty(last(split({domain}, '.')))))"
        )
    checks = sequence(
        ("Validate_Mail_Configuration", {
            "type": "ParseJson",
            "inputs": {
                "content": {"Sender": "@parameters('SenderMailbox')", "Recipient": "@parameters('RecipientEmail')"},
                "schema": {
                    "type": "object", "required": ["Sender", "Recipient"],
                    "properties": {key: {"type": "string", "minLength": 3} for key in ("Sender", "Recipient")},
                },
            },
        }),
        ("Find_Invalid_Mail_Characters", {
            "type": "Query",
            "inputs": {
                "from": "@json('" + json.dumps(forbidden, ensure_ascii=True, separators=(",", ":")) + "')",
                "where": "@or(contains(parameters('SenderMailbox'), item()), contains(parameters('RecipientEmail'), item()))",
            },
        }),
        ("Validate_Mail_Addresses", assertion(
            "@and(empty(body('Find_Invalid_Mail_Characters')), " + ", ".join(shapes) + ")"
        )),
    )
    del checks["Validate_Mail_Configuration"]["runAfter"]
    return checks


def workflow_call(name: str, body: dict) -> dict:
    return {
        "type": "Workflow",
        "inputs": {
            "host": {
                "triggerName": "manual",
                "workflow": {"id": f"[resourceId('Microsoft.Logic/workflows', variables('{name}'))]"},
            },
            "body": body,
            "retryPolicy": {"type": "none"},
        },
    }


def definition(actions: dict, parameters: dict, trigger: dict) -> dict:
    return {
        "$schema": WF_SCHEMA, "contentVersion": "1.0.0.0",
        "parameters": parameters, "triggers": trigger, "actions": actions, "outputs": {},
    }


def request_trigger(schema: dict) -> dict:
    return {"manual": {
        "type": "Request", "kind": "Http", "inputs": {"schema": schema},
    }}


def native_definitions(swagger: dict) -> dict:
    definitions = copy.deepcopy(swagger["definitions"])
    definitions["Cve"]["properties"]["id"] = {"type": "string", "minLength": 13}
    definitions["BaseScore"]["oneOf"] = [
        {"properties": {"baseSeverity": {"enum": ["CRITICAL"]}, "baseScore": {"minimum": 9}}},
        {"properties": {"baseSeverity": {"enum": ["NONE", "LOW", "MEDIUM", "HIGH"]}}},
    ]
    return definitions


def restore_cpe_component(index: int) -> str:
    return (
        f"replace(replace(replace(item()?['parts'][{index}], "
        "'%3A', '\\:'), '%5C', '\\\\'), '%25', '%')"
    )


def formatter_definition(swagger: dict) -> dict:
    schema = {
        "type": "object", "required": ["ReportDate", "PublishedCount", "Cves", "CollectedAt"],
        "additionalProperties": False,
        "properties": {
            "ReportDate": {"type": "string", "minLength": 10, "maxLength": 10},
            "PublishedCount": {"type": "integer", "minimum": 0},
            "CollectedAt": {"type": "string"},
            "Cves": {"type": "array", "items": {"$ref": "#/definitions/Cve"}},
        },
        "definitions": native_definitions(swagger),
    }
    protected = "@split(replace(replace(replace(item()?['criteria'], '%', '%25'), '\\\\', '%5C'), '\\:', '%3A'), ':')"
    match = "item()?['match']"
    cpe_line = (
        "@concat('  Vendor: ', " + restore_cpe_component(3) +
        ", ' / Product: ', " + restore_cpe_component(4) +
        ", ' / Version: ', " + restore_cpe_component(5) +
        f", {LF}, '    CPE: ', {match}?['criteria'], {LF}, "
        f"'    versionStartIncluding: ', string(coalesce({match}?['versionStartIncluding'], 'Not specified')), {LF}, "
        f"'    versionStartExcluding: ', string(coalesce({match}?['versionStartExcluding'], 'Not specified')), {LF}, "
        f"'    versionEndIncluding: ', string(coalesce({match}?['versionEndIncluding'], 'Not specified')), {LF}, "
        f"'    versionEndExcluding: ', string(coalesce({match}?['versionEndExcluding'], 'Not specified')))"
    )
    # One Filter/Select/Join per node replaces five actions per CPE match.
    cpe_entries = [
        ("Vulnerable_CPE_Matches", {"type": "Query", "inputs": {
            "from": "@coalesce(outputs('Current_Node')?['cpeMatch'], json('[]'))",
            "where": "@equals(item()?['vulnerable'], true)"}}),
        ("CPE_Parts", {"type": "Select", "inputs": {
            "from": "@body('Vulnerable_CPE_Matches')",
            "select": {"parts": protected, "match": "@item()"}}}),
        ("Malformed_CPE_Parts", {"type": "Query", "inputs": {
            "from": "@body('CPE_Parts')", "where": "@not(equals(length(item()?['parts']), 13))"}}),
        ("Validate_CPE_Components", assertion("@empty(body('Malformed_CPE_Parts'))")),
        ("Invalid_CPE_Prefix", {"type": "Query", "inputs": {
            "from": "@body('CPE_Parts')",
            "where": "@not(and(equals(item()?['parts'][0], 'cpe'), equals(item()?['parts'][1], '2.3')))"}}),
        ("Validate_CPE_Prefix", assertion("@empty(body('Invalid_CPE_Prefix'))")),
        ("CPE_Lines", {"type": "Select", "inputs": {"from": "@body('CPE_Parts')", "select": cpe_line}}),
        ("If_Any_Vulnerable_CPE", condition("@not(empty(body('CPE_Parts')))", sequence(
            ("Append_CPE_Lines", append("ReportBody", f"@concat(join(body('CPE_Lines'), {LF}), {LF})")),
            ("Remember_Vulnerable_Match", setvar("HadVulnerableMatch", True)),
        ))),
    ]
    queue = sequence(
        ("Current_Node", compose("@first(variables('NodeQueue'))")),
        ("Remaining_Nodes", compose("@skip(variables('NodeQueue'), 1)")),
        ("Dequeue_Node", setvar("NodeQueue", "@outputs('Remaining_Nodes')")),
        ("For_each_Node", foreach("@coalesce(outputs('Current_Node')?['nodes'], json('[]'))", sequence(
            ("Enqueue_Node", append("NodeQueue", "@items('For_each_Node')", array=True)),
        ))),
        ("For_each_Child", foreach("@coalesce(outputs('Current_Node')?['children'], json('[]'))", sequence(
            ("Enqueue_Child", append("NodeQueue", "@items('For_each_Child')", array=True)),
        ))),
        *cpe_entries,
    )
    cve = "items('For_each_CVE')"
    def metric_block(suffix: str, version: str) -> str:
        return (
            f"'CVSS {version} assessments:', {LF}, "
            f"if(empty(body('Metric{suffix}_Lines')), "
            f"concat('  baseScore: Not provided by NVD; baseSeverity: Not provided by NVD', {LF}), "
            f"concat(join(body('Metric{suffix}_Lines'), {LF}), {LF})), "
        )

    entries = [
        ("Validate_Formatted_CVE_Id", assertion("@" + valid_cve_id(f"{cve}?['id']"))),
        ("Advance_CVE_Number", {"type": "IncrementVariable", "inputs": {"name": "CveNumber", "value": 1}}),
        ("Description_Lines", {"type": "Select", "inputs": {
            "from": f"@coalesce({cve}?['descriptions'], json('[]'))",
            "select": "@concat('  [', coalesce(item()?['lang'], 'unspecified'), '] ', item()?['value'])"}}),
    ]
    for key, suffix in (("cvssMetricV40", "40"), ("cvssMetricV31", "31")):
        entries.append((f"Metric{suffix}_Lines", {"type": "Select", "inputs": {
            "from": f"@coalesce({cve}?['metrics']?['{key}'], json('[]'))",
            "select": (
                "@concat('  baseScore: ', string(item()?['cvssData']?['baseScore']), "
                "'; baseSeverity: ', item()?['cvssData']?['baseSeverity'], "
                "'; source: ', coalesce(item()?['source'], 'unspecified'), "
                "'; type: ', coalesce(item()?['type'], 'unspecified'))")}}))
    # Header, descriptions, both CVSS blocks and the affected heading are one append instead of eight.
    entries.append(("Append_CVE_Section", append("ReportBody",
        f"@concat(triggerBody()?['ReportDate'], ' #', string(variables('CveNumber')), ' ', {cve}?['id'], ' ', '{'-' * 72}', {LF}, "
        f"'CVE: ', {cve}?['id'], {LF}, 'URL: https://nvd.nist.gov/vuln/detail/', {cve}?['id'], {LF}, "
        f"'Published (NVD UTC): ', {cve}?['published'], {LF}, "
        f"'Last modified (NVD UTC): ', coalesce({cve}?['lastModified'], 'Not provided by NVD'), {LF}, "
        f"'Description (full NVD text):', {LF}, "
        f"if(empty(body('Description_Lines')), concat('  Not provided by NVD.', {LF}), "
        f"concat(join(body('Description_Lines'), {LF}), {LF})), "
        + metric_block("40", "4.0") + metric_block("31", "3.1") +
        f"'Affected Vendor / Product / Version (vulnerable CPE matches):', {LF})")))
    entries += [
        ("Reset_Match_Flag", setvar("HadVulnerableMatch", False)),
        ("Initialize_Node_Queue", setvar("NodeQueue", f"@coalesce({cve}?['configurations'], json('[]'))")),
        ("If_Config_Exists", condition("@not(empty(variables('NodeQueue')))", sequence(
            ("Walk_CPE_Tree", until("@empty(variables('NodeQueue'))", queue)),
        ))),
        ("Append_Full_Applicability", append("ReportBody",
            f"@concat(if(variables('HadVulnerableMatch'), '', "
            f"concat('  Not provided by NVD; see source affected data below.', {LF})), "
            f"'CPE notes: * = ANY, - = NA; escaped component text is preserved.', {LF}, "
            f"'Full applicability logic (including AND/OR/negate and environmental conditions):', {LF}, "
            f"string(coalesce({cve}?['configurations'], json('[]'))), {LF}, "
            f"'NVD affected data (all vendors/products/versions/status/changes):', {LF}, "
            f"string(coalesce({cve}?['affected'], json('[]'))), {LF}, {LF})")),
    ]
    actions = sequence(
        *initialize({
            "ReportBody": ("string", ""),
            "NodeQueue": ("array", []),
            "HadVulnerableMatch": ("boolean", False),
            "CveNumber": ("integer", 0),
        }),
        ("Validate_Input", {"type": "ParseJson", "inputs": {"content": "@triggerBody()", "schema": schema}}),
        ("Validate_Formatter_Report_Date", assertion(
            "@equals(formatDateTime(triggerBody()?['ReportDate'], 'yyyy-MM-dd'), triggerBody()?['ReportDate'])"
        )),
        ("Append_Report_Header", append("ReportBody",
            f"@concat('NVD CRITICAL Daily Vulnerability Report', {LF}, "
            f"'Report date (JST): ', triggerBody()?['ReportDate'], {LF}, "
            f"'NVD collected at (UTC): ', triggerBody()?['CollectedAt'], {LF}, "
            f"'Daily vulnerability count (distinct CVEs): ', string(length(triggerBody()?['Cves'])), {LF}, "
            f"'All published CVEs inspected: ', string(triggerBody()?['PublishedCount']), {LF}, "
            f"'Selection: CVSS 4.0 CRITICAL OR CVSS 3.1 CRITICAL (all assessment sources).', {LF}, "
            f"'Completeness: all pages verified and two complete snapshots matched.', {LF}, "
            f"'LLM used: false; token overflow: not applicable.', {LF}, {LF})")),
        ("For_each_CVE", foreach("@sort(triggerBody()?['Cves'], 'id')", sequence(*entries))),
        ("If_Zero_Matches", condition("@equals(length(triggerBody()?['Cves']), 0)", sequence(
            ("Append_Zero_Matches", append("ReportBody", f"@concat('No CVEs matched in the completed NVD snapshot.', {LF})")),
        ))),
        ("Append_Report_Scope", append("ReportBody",
            f"@concat('Scope: NVD assessments available at collection time, grouped by JST publication day. "
            f"Later enrichment and publication corrections are not retroactively included.', {LF})")),
        ("Return_TEXT", {
            "type": "Response", "kind": "Http",
            "inputs": {"statusCode": 200, "headers": {"Content-Type": "application/json"},
                       "body": {"ReportBody": "@variables('ReportBody')",
                                "CriticalCount": "@length(triggerBody()?['Cves'])",
                                "LLMUsed": False}},
        }),
    )
    return definition(actions, {}, request_trigger(schema))


def source_preparation(swagger: dict) -> dict:
    page_schema = copy.deepcopy(swagger['definitions']['Page'])
    page_schema['definitions'] = native_definitions(swagger)
    page_actions = sequence(('NVD_Rate_Limit_Delay', {'type': 'Wait', 'inputs': {'interval': {'count': 7, 'unit': 'Second'}}}), ('Read_NVD_Page', {'type': 'ApiConnection', 'inputs': {'host': {'connection': {'name': "@parameters('$connections')['nvd']['connectionId']"}}, 'method': 'get', 'path': '/rest/json/cves/2.0', 'headers': {'apiKey': "@parameters('NvdApiKey')"}, 'queries': {'pubStartDate': "@outputs('Publication_Start_UTC')", 'pubEndDate': "@outputs('Publication_End_UTC')", 'startIndex': "@variables('PageIndex')", 'resultsPerPage': "@parameters('NvdPageSize')"}, 'retryPolicy': {'type': 'exponential', 'count': 4, 'interval': 'PT7S'}}, 'runtimeConfiguration': {'secureData': {'properties': ['inputs', 'outputs']}}}), ('Parse_NVD_Page', {'type': 'ParseJson', 'inputs': {'content': "@body('Read_NVD_Page')", 'schema': page_schema}}), ('Set_Page_Error_Context', setvar('ErrorCode', 'NVD_PAGE_OR_COUNT_MISMATCH')), ('Effective_Expected_Total', compose("@if(equals(variables('ExpectedTotal'), -1), body('Parse_NVD_Page')?['totalResults'], variables('ExpectedTotal'))")), ('Set_Expected_Total', setvar('ExpectedTotal', "@outputs('Effective_Expected_Total')")), ('Validate_Page_Metadata', assertion("@and(equals(body('Parse_NVD_Page')?['startIndex'], variables('PageIndex')), equals(body('Parse_NVD_Page')?['totalResults'], variables('ExpectedTotal')), lessOrEquals(body('Parse_NVD_Page')?['resultsPerPage'], parameters('NvdPageSize')), lessOrEquals(length(body('Parse_NVD_Page')?['vulnerabilities']), body('Parse_NVD_Page')?['resultsPerPage']), lessOrEquals(add(variables('PageIndex'), length(body('Parse_NVD_Page')?['vulnerabilities'])), variables('ExpectedTotal')), or(greater(length(body('Parse_NVD_Page')?['vulnerabilities']), 0), equals(variables('PageIndex'), variables('ExpectedTotal'))))")), ('Find_Out_Of_Window_CVEs', {'type': 'Query', 'inputs': {'from': "@body('Parse_NVD_Page')?['vulnerabilities']", 'where': "@not(and(greaterOrEquals(ticks(item()?['cve']?['published']), ticks(outputs('Publication_Start_UTC'))), less(ticks(item()?['cve']?['published']), ticks(outputs('Publication_Next_Midnight_UTC')))))"}}), ('Validate_Publication_Window', assertion("@empty(body('Find_Out_Of_Window_CVEs'))")), *cve_ids_validation("@body('Parse_NVD_Page')?['vulnerabilities']", "item()?['cve']?['id']").items(), ('Select_Page_Ids', {'type': 'Select', 'inputs': {'from': "@body('Parse_NVD_Page')?['vulnerabilities']", 'select': "@item()?['cve']?['id']"}}), ('Select_Page_CVEs', {'type': 'Select', 'inputs': {'from': "@body('Parse_NVD_Page')?['vulnerabilities']", 'select': "@item()?['cve']"}}), ('Merged_Ids', compose("@union(variables('CurrentIds'), body('Select_Page_Ids'))")), ('Validate_No_Duplicate_Ids', assertion("@equals(length(outputs('Merged_Ids')), add(length(variables('CurrentIds')), length(body('Select_Page_Ids'))))")), ('Merged_CVEs', compose("@union(variables('CurrentCves'), body('Select_Page_CVEs'))")), ('Remember_Current_Ids', setvar('CurrentIds', "@outputs('Merged_Ids')")), ('Remember_Current_CVEs', setvar('CurrentCves', "@outputs('Merged_CVEs')")), ('Advance_Page_Index', {'type': 'IncrementVariable', 'inputs': {'name': 'PageIndex', 'value': "@length(body('Parse_NVD_Page')?['vulnerabilities'])"}}), ('Set_Page_Done', setvar('PageDone', "@equals(variables('PageIndex'), variables('ExpectedTotal'))")))
    page_scope = sequence(('Read_And_Validate_Page', scope(page_actions)), ('Stop_After_Page_Failure', {**setvar('CollectError', True), 'runAfter': {'Read_And_Validate_Page': FAILED}}))
    scan_actions = sequence(('Reset_Current_CVEs', setvar('CurrentCves', [])), ('Reset_Current_Ids', setvar('CurrentIds', [])), ('Reset_Page_Index', setvar('PageIndex', 0)), ('Reset_Total', setvar('ExpectedTotal', -1)), ('Reset_Page_Done', setvar('PageDone', False)), ('Advance_Scan_Number', {'type': 'IncrementVariable', 'inputs': {'name': 'ScanNumber', 'value': 1}}), ('Set_NVD_Error_Context', setvar('ErrorCode', 'NVD_GET_SCHEMA_OR_PAGE_FAILURE')), ('Read_All_Pages', until("@or(variables('PageDone'), variables('CollectError'))", page_scope)), ('Validate_Full_Count', assertion("@and(equals(length(variables('CurrentIds')), variables('ExpectedTotal')), equals(length(variables('CurrentCves')), variables('ExpectedTotal')))")), ('Sorted_Current_Snapshot', compose("@sort(variables('CurrentCves'), 'id')")), ('If_Snapshots_Match', condition("@and(variables('HasPrevious'), equals(outputs('Sorted_Current_Snapshot'), variables('PreviousSnapshot')))", sequence(('Set_Snapshot_Matched', setvar('SnapshotMatched', True))), sequence(('Remember_Previous_Snapshot', setvar('PreviousSnapshot', "@outputs('Sorted_Current_Snapshot')")), ('Remember_Previous_Exists', setvar('HasPrevious', True))))))
    scan_scope = sequence(('Collect_One_Snapshot', scope(scan_actions)), ('Stop_After_Scan_Failure', {**setvar('CollectError', True), 'runAfter': {'Collect_One_Snapshot': FAILED}}))
    filter_actions = sequence(('Critical_V4_Assessments', {'type': 'Query', 'inputs': {'from': "@coalesce(items('Check_All_CVEs')?['metrics']?['cvssMetricV40'], json('[]'))", 'where': "@and(equals(item()?['cvssData']?['version'], '4.0'), equals(item()?['cvssData']?['baseSeverity'], 'CRITICAL'))"}}), ('Critical_V31_Assessments', {'type': 'Query', 'inputs': {'from': "@coalesce(items('Check_All_CVEs')?['metrics']?['cvssMetricV31'], json('[]'))", 'where': "@and(equals(item()?['cvssData']?['version'], '3.1'), equals(item()?['cvssData']?['baseSeverity'], 'CRITICAL'))"}}), ('If_Either_Critical', condition("@or(not(empty(body('Critical_V4_Assessments'))), not(empty(body('Critical_V31_Assessments'))))", sequence(('Remember_Critical_CVE', append('CriticalCves', "@items('Check_All_CVEs')", array=True))))))
    return sequence(('Set_Key_Error_Context', setvar('ErrorCode', 'NVD_KEY_NOT_CONFIGURED')), ('Validate_NVD_Key', assertion("@and(greaterOrEquals(length(parameters('NvdApiKey')), 16), not(startsWith(parameters('NvdApiKey'), '<')), not(contains(parameters('NvdApiKey'), ' ')), not(contains(parameters('NvdApiKey'), decodeUriComponent('%0A'))), not(contains(parameters('NvdApiKey'), decodeUriComponent('%0D'))), not(contains(parameters('NvdApiKey'), decodeUriComponent('%09'))))")), ('Publication_Start_UTC', compose("@convertTimeZone(concat(variables('ReportDate'), 'T00:00:00'), 'Tokyo Standard Time', 'UTC', 'yyyy-MM-ddTHH:mm:ss.fffZ')")), ('Publication_Next_Midnight_UTC', compose("@addDays(outputs('Publication_Start_UTC'), 1)")), ('Publication_End_UTC', compose("@concat(formatDateTime(addSeconds(outputs('Publication_Next_Midnight_UTC'), -1), 'yyyy-MM-ddTHH:mm:ss'), '.999Z')")), ('Collect_Matching_Snapshots', until("@or(variables('SnapshotMatched'), variables('CollectError'), greaterOrEquals(variables('ScanNumber'), 3))", scan_scope, count=3, timeout='PT12H')), ('Set_Snapshot_Error_Context', setvar('ErrorCode', 'NVD_SNAPSHOT_UNSTABLE')), ('Validate_Matched_Snapshots', assertion("@and(variables('SnapshotMatched'), not(variables('CollectError')))")), ('Remember_Published_Count', setvar('PublishedCount', "@length(variables('CurrentCves'))")), ('Set_Filter_Error_Context', setvar('ErrorCode', 'CVSS_EVALUATION_FAILED')), ('Candidate_Critical_CVEs', {'type': 'Query', 'inputs': {'from': "@variables('CurrentCves')", 'where': "@contains(string(coalesce(item()?['metrics'], json('{}'))), 'CRITICAL')"}}), ('Check_All_CVEs', foreach("@sort(body('Candidate_Critical_CVEs'), 'id')", filter_actions)), ('Remember_Critical_Count', setvar('CriticalCount', "@length(variables('CriticalCves'))")), ('Remember_Collection_Time', setvar('CollectedAt', '@utcNow()')), ('Record_Complete_Source', compose({'ReportDate': "@variables('ReportDate')", 'CollectedAt': "@variables('CollectedAt')", 'PublicationStartUtc': "@outputs('Publication_Start_UTC')", 'PublicationEndUtcExclusive': "@outputs('Publication_Next_Midnight_UTC')", 'PublishedCount': "@variables('PublishedCount')", 'ScanCount': "@variables('ScanNumber')", 'Comparison': 'Two complete sorted CVE arrays matched by value', 'Cves': "@sort(variables('CurrentCves'), 'id')", 'LLMUsed': False})), ('Set_Format_Error_Context', setvar('ErrorCode', 'NATIVE_REPORT_FORMAT_FAILED')), ('Format_Complete_Report', workflow_call('formatterName', {'ReportDate': "@variables('ReportDate')", 'CollectedAt': "@variables('CollectedAt')", 'PublishedCount': "@variables('PublishedCount')", 'Cves': "@variables('CriticalCves')"})), ('Remember_Report_Body', setvar('ReportBody', "@body('Format_Complete_Report')?['ReportBody']")), ('Validate_Formatter_Count', assertion("@and(equals(body('Format_Complete_Report')?['CriticalCount'], variables('CriticalCount')), equals(body('Format_Complete_Report')?['LLMUsed'], false))")), ('Report_Subject', compose("@concat('NVD CRITICAL Daily ', variables('ReportDate'), ' JST (', string(variables('CriticalCount')), ' CVEs)')")), ('Mail_Body_Html', compose(MAIL_BODY_HTML)), ('Mail_Request_Object', compose({'To': "@parameters('RecipientEmail')", 'Subject': "@outputs('Report_Subject')", 'Body': "@outputs('Mail_Body_Html')", 'From': "@parameters('SenderMailbox')", 'Importance': 'Normal'})), ('Mail_Request_JSON', compose("@string(outputs('Mail_Request_Object'))")), ('Encode_Mail_Request', compose("@base64(outputs('Mail_Request_JSON'))")), ('Remember_Encoded_Request', setvar('RequestBase64', "@outputs('Encode_Mail_Request')")), ('Exact_Request_Bytes', compose("@sub(div(mul(length(variables('RequestBase64')), 3), 4), if(endsWith(variables('RequestBase64'), '=='), 2, if(endsWith(variables('RequestBase64'), '='), 1, 0)))")), ('Remember_Request_Bytes', setvar('RequestBytes', "@outputs('Exact_Request_Bytes')")), ('Record_TEXT_Report', compose("@variables('ReportBody')")), ('Set_Prepared_Flag', setvar('Prepared', True)), ('Set_Ready_Result', setvar('ResultStatus', 'ready')))




def preparation_stage(name: str, actions: dict) -> dict:
    failures = sequence((f'{name}_Failed_Actions', {'type': 'Query', 'inputs': {'from': f"@result('{name}_Try')", 'where': '@contains(json(\'["Failed","TimedOut"]\'), item()?[\'status\'])'}, 'runtimeConfiguration': {'secureData': {'properties': ['inputs', 'outputs']}}}), (f'{name}_Failure_Summary', {'type': 'Select', 'inputs': {'from': f"@body('{name}_Failed_Actions')", 'select': {'action': "@item()?['name']", 'status': "@item()?['status']", 'code': "@coalesce(item()?['error']?['code'], 'not_exposed')"}}, 'runtimeConfiguration': {'secureData': {'properties': ['inputs', 'outputs']}}}), (f'{name}_Reason', setvar('ErrorReason', f"@concat(variables('ErrorCode'), '; run ', workflow().run.name, '; ', take(string(body('{name}_Failure_Summary')), 800))")), (f'{name}_Result', setvar('ResultStatus', "@if(equals(variables('ErrorCode'), 'NVD_KEY_NOT_CONFIGURED'), 'configuration_required', 'preparation_failed')")))
    return sequence((f'{name}_Try', scope(actions)), (f'{name}_Catch', scope(failures, {f'{name}_Try': FAILED})))


def mail_delivery() -> dict:
    accepted = sequence(('Remember_Acceptance_Id', setvar('MailRequestId', "@coalesce(outputs('Send_Office365_Mail')?['headers']?['x-ms-request-id'], outputs('Send_Office365_Mail')?['headers']?['X-MS-Request-ID'], outputs('Send_Office365_Mail')?['headers']?['request-id'], 'Not returned')")), ('Set_Accepted_Result', setvar('ResultStatus', 'mail_accepted')), ('Clear_Accepted_Error', setvar('ErrorCode', "@concat('')")), ('Clear_Accepted_Reason', setvar('ErrorReason', "@concat('')")))
    throttled = sequence(('Retry_After_Seconds', compose("@string(coalesce(outputs('Send_Office365_Mail')?['headers']?['Retry-After'], outputs('Send_Office365_Mail')?['headers']?['retry-after'], '900'))")), ('Validate_Retry_After', {'type': 'ParseJson', 'inputs': {'content': "@outputs('Retry_After_Seconds')", 'schema': {'type': 'string', 'minLength': 1, 'maxLength': 6}}}), ('Validate_Retry_After_Digits', assertion('@' + digits_only("outputs('Retry_After_Seconds')"))), ('Set_Not_Before', setvar('NotBeforeUtc', "@addSeconds(utcNow(), max(1, int(outputs('Retry_After_Seconds'))))")), ('Set_Throttled_Result', setvar('ResultStatus', 'retry_wait')), ('Set_Throttled_Code', setvar('ErrorCode', 'MAIL_THROTTLED')), ('Set_Throttled_Reason', setvar('ErrorReason', "@concat('Office 365 returned HTTP 429; Retry-After seconds ', outputs('Retry_After_Seconds'), '. Missing header uses 900 seconds; only this explicit rejection permits automatic retry.')")), ('Allow_429_Retry', setvar('RetryMail', True)))
    rejected = sequence(('Set_Rejected_Code', setvar('ErrorCode', "@if(equals(variables('MailHttpStatus'), 413), 'MAIL_TOO_LARGE', concat('MAIL_REJECTED_', string(variables('MailHttpStatus'))))")), ('Set_Rejected_Reason', setvar('ErrorReason', "@concat('Office 365 explicitly rejected the single mail: HTTP ', string(variables('MailHttpStatus')), '. Nothing was truncated, split or attached. Inspect this run before manual retry.')")), ('Set_Rejected_Result', setvar('ResultStatus', 'blocked')))
    uncertain = sequence(('Set_Uncertain_Code', setvar('ErrorCode', 'MAIL_DELIVERY_UNCERTAIN')), ('Set_Uncertain_Reason', setvar('ErrorReason', "@concat('Office 365 send acceptance is unknown (HTTP ', string(variables('MailHttpStatus')), '). No automatic resend. Check this run, Sent Items and message trace before any manual execution.')")), ('Set_Uncertain_Result', setvar('ResultStatus', 'delivery_uncertain')))
    send = {'type': 'ApiConnection', 'inputs': {'host': {'connection': {'name': "@parameters('$connections')['office365']['connectionId']"}}, 'method': 'post', 'path': '/v2/Mail', 'body': "@outputs('Mail_Request_Object')", 'retryPolicy': {'type': 'none'}}, 'runtimeConfiguration': {'secureData': {'properties': ['inputs']}}}
    attempt = sequence(('Clear_Mail_Retry', setvar('RetryMail', False)), ('Reset_Mail_Attempt_Result', setvar('ResultStatus', 'submitting')), ('If_Retry_Time_Is_Future', condition("@greater(ticks(variables('NotBeforeUtc')), ticks(utcNow()))", sequence(('Wait_Mail_Retry_After', {'type': 'Wait', 'inputs': {'until': {'timestamp': "@variables('NotBeforeUtc')"}}})))), ('Advance_Mail_Attempt', {'type': 'IncrementVariable', 'inputs': {'name': 'MailAttempt', 'value': 1}}), ('Record_Submission_Attempt', compose({'ReportDate': "@variables('ReportDate')", 'Attempt': "@variables('MailAttempt')", 'RunId': '@workflow().run.name', 'Status': 'submitting', 'RequestBytes': "@variables('RequestBytes')"})), ('Send_Office365_Mail', send), ('Remember_Mail_HTTP_Status', {**setvar('MailHttpStatus', "@int(coalesce(outputs('Send_Office365_Mail')?['statusCode'], 0))"), 'runAfter': {'Send_Office365_Mail': ALL}}), ('Mail_Response_Class', compose("@if(or(equals(variables('MailHttpStatus'), 200), equals(variables('MailHttpStatus'), 202)), 'accepted', if(equals(variables('MailHttpStatus'), 429), 'retry', if(and(greaterOrEquals(variables('MailHttpStatus'), 400), less(variables('MailHttpStatus'), 500), not(equals(variables('MailHttpStatus'), 408))), 'rejected', 'uncertain')))")), ('Classify_Mail_Response', {'type': 'Switch', 'expression': "@outputs('Mail_Response_Class')", 'cases': {'Accepted': {'case': 'accepted', 'actions': accepted}, 'Throttled': {'case': 'retry', 'actions': throttled}, 'Rejected': {'case': 'rejected', 'actions': rejected}}, 'default': {'actions': uncertain}}))
    return until("@or(not(variables('RetryMail')), greaterOrEquals(variables('MailAttempt'), 4))", attempt, count=4, timeout='P2D')


def worker_definition(swagger: dict) -> dict:
    request_schema = {'type': 'object', 'additionalProperties': False, 'required': ['ReportDate'], 'properties': {'ReportDate': {'type': 'string', 'minLength': 10, 'maxLength': 10}}}
    validate = sequence(('Validate_Worker_Request', {'type': 'ParseJson', 'inputs': {'content': '@triggerBody()', 'schema': request_schema}}), *mail_configuration_validation().items(), ('Current_Due_Date', compose(DUE_DATE)), ('Validate_Report_Date', assertion("@and(equals(formatDateTime(variables('ReportDate'), 'yyyy-MM-dd'), variables('ReportDate')), greaterOrEquals(ticks(variables('ReportDate')), ticks(parameters('FirstReportDate'))), lessOrEquals(ticks(variables('ReportDate')), ticks(outputs('Current_Due_Date'))))")))
    validate.update(sequence(*[(name, action) for name, action in source_preparation(swagger).items()]))
    validate['Set_Key_Error_Context']['runAfter'] = {'Validate_Report_Date': ['Succeeded']}
    too_large = sequence(('Set_Size_Error_Code', setvar('ErrorCode', 'MAIL_TOO_LARGE')), ('Set_Size_Error_Reason', setvar('ErrorReason', "@concat('Exact mail request ', string(variables('RequestBytes')), ' bytes exceeds configured ', string(parameters('MaxMailRequestBytes')), '. Full prepared TEXT is retained in this run history; no truncation or splitting.')")), ('Set_Too_Large_Result', setvar('ResultStatus', 'blocked')))
    delivery_failure = sequence(('If_Response_Not_Classified', condition('@not(contains(json(\'["mail_accepted","blocked","retry_wait","delivery_uncertain"]\'), variables(\'ResultStatus\')))', sequence(('Set_Delivery_Error', setvar('ErrorCode', 'MAIL_RESULT_UNCERTAIN')), ('Set_Delivery_Reason', setvar('ErrorReason', "@concat('Unable to complete mail result classification. Run ', workflow().run.name, '. No automatic resend; inspect history and message trace.')")), ('Set_Delivery_Uncertain', setvar('ResultStatus', 'delivery_uncertain'))))))
    delivery = sequence(('Try_Delivery', scope(sequence(('Submit_One_Mail', mail_delivery())))), ('Catch_Delivery', scope(delivery_failure, {'Try_Delivery': FAILED})))
    initial = {'ReportDate': ('string', "@coalesce(triggerBody()?['ReportDate'], '')"), 'Prepared': ('boolean', False), 'ResultStatus': ('string', 'internal_error'), 'ErrorCode': ('string', 'REQUEST_OR_PREPARATION_FAILED'), 'ErrorReason': ('string', 'No completed phase has been recorded.'), 'PublishedCount': ('integer', -1), 'CriticalCount': ('integer', -1), 'ReportBody': ('string', ''), 'RequestBase64': ('string', ''), 'RequestBytes': ('integer', -1), 'CollectedAt': ('string', ''), 'ScanNumber': ('integer', 0), 'CurrentCves': ('array', []), 'CurrentIds': ('array', []), 'PreviousSnapshot': ('array', []), 'HasPrevious': ('boolean', False), 'SnapshotMatched': ('boolean', False), 'CollectError': ('boolean', False), 'PageIndex': ('integer', 0), 'ExpectedTotal': ('integer', -1), 'PageDone': ('boolean', False), 'CriticalCves': ('array', []), 'MailAttempt': ('integer', 0), 'RetryMail': ('boolean', False), 'MailHttpStatus': ('integer', 0), 'MailRequestId': ('string', ''), 'NotBeforeUtc': ('string', '1900-01-01T00:00:00Z')}
    report = {'ReportDate': "@variables('ReportDate')", 'Status': "@variables('ResultStatus')", 'PublishedCount': "@if(less(variables('PublishedCount'), 0), json('null'), variables('PublishedCount'))", 'CriticalCount': "@if(less(variables('CriticalCount'), 0), json('null'), variables('CriticalCount'))", 'RequestBytes': "@if(less(variables('RequestBytes'), 0), json('null'), variables('RequestBytes'))", 'MailHttpStatus': "@variables('MailHttpStatus')", 'MailRequestId': "@variables('MailRequestId')", 'ErrorCode': "@variables('ErrorCode')", 'ErrorReason': "@variables('ErrorReason')", 'CollectedAt': "@variables('CollectedAt')", 'RunId': '@workflow().run.name', 'LLMUsed': False, 'CrossRunDuplicateProtection': False, 'MailAcceptanceIsNotDelivery': True, 'MailSendingEnabled': "@parameters('MailSendingEnabled')", 'NvdKeyConfigured': "@and(greaterOrEquals(length(parameters('NvdApiKey')), 16), not(startsWith(parameters('NvdApiKey'), '<')), not(contains(parameters('NvdApiKey'), ' ')), not(contains(parameters('NvdApiKey'), decodeUriComponent('%0A'))), not(contains(parameters('NvdApiKey'), decodeUriComponent('%0D'))), not(contains(parameters('NvdApiKey'), decodeUriComponent('%09'))))"}
    audit = compose(report)
    audit['trackedProperties'] = {key: f"@action()?['inputs']?['{key}']" for key in ('ReportDate', 'Status', 'PublishedCount', 'CriticalCount', 'RequestBytes', 'MailHttpStatus', 'MailRequestId', 'ErrorCode', 'ErrorReason', 'CollectedAt', 'RunId', 'LLMUsed', 'CrossRunDuplicateProtection', 'MailAcceptanceIsNotDelivery', 'MailSendingEnabled', 'NvdKeyConfigured')}
    actions = sequence(*initialize(initial), ('Prepare_This_Run', scope(preparation_stage('Prepare', validate))), ('If_Prepared', {**condition("@variables('Prepared')", sequence(('If_One_Mail_Fits', condition("@lessOrEquals(variables('RequestBytes'), parameters('MaxMailRequestBytes'))", sequence(('If_Mail_Sending_Enabled', condition("@parameters('MailSendingEnabled')", delivery, sequence(('Set_Preview_Code', setvar('ErrorCode', 'MAIL_SENDING_DISABLED')), ('Set_Preview_Reason', setvar('ErrorReason', 'Complete TEXT and request prepared in this run; no mail was sent. Inspect history before any rerun.')))))), too_large)))), 'runAfter': {'Prepare_This_Run': ALL}}), ('Record_Audit_Event', {**audit, 'runAfter': {'If_Prepared': ALL}}), ('Return_Day_State', {'type': 'Response', 'kind': 'Http', 'inputs': {'statusCode': "@if(equals(variables('ResultStatus'), 'mail_accepted'), 200, 409)", 'headers': {'Content-Type': 'application/json'}, 'body': "@outputs('Record_Audit_Event')"}}), ('If_Day_Not_Accepted', condition("@not(equals(variables('ResultStatus'), 'mail_accepted'))", sequence(('Fail_Unaccepted_Day', {'type': 'Terminate', 'inputs': {'runStatus': 'Failed', 'runError': {'code': "@variables('ErrorCode')", 'message': "@variables('ErrorReason')"}}})))))
    return definition(actions, {'$connections': {'type': 'Object', 'defaultValue': {}}, 'SenderMailbox': {'type': 'String', 'defaultValue': "[parameters('senderMailbox')]"}, 'RecipientEmail': {'type': 'String', 'defaultValue': "[parameters('recipientEmail')]"}, 'FirstReportDate': {'type': 'String', 'defaultValue': "[parameters('firstReportDate')]"}, 'MailSendingEnabled': {'type': 'Bool', 'defaultValue': "[parameters('mailSendingEnabled')]"}, 'MaxMailRequestBytes': {'type': 'Int', 'defaultValue': "[parameters('maxMailRequestBytes')]"}, 'NvdPageSize': {'type': 'Int', 'defaultValue': "[parameters('nvdPageSize')]"}, 'NvdApiKey': {'type': 'SecureString'}}, request_trigger(request_schema))


def scheduler_definition() -> dict:
    result = sequence(('Due_Publication_Date', compose(DUE_DATE)), ('If_Date_Is_In_Scope', condition("@greaterOrEquals(ticks(outputs('Due_Publication_Date')), ticks(parameters('FirstReportDate')))", sequence(('Invoke_Day_Worker', workflow_call('workerName', {'ReportDate': "@outputs('Due_Publication_Date')"})), ('If_Day_Not_Accepted', {**condition("@not(and(equals(actions('Invoke_Day_Worker')?['status'], 'Succeeded'), equals(body('Invoke_Day_Worker')?['Status'], 'mail_accepted')))", sequence(('Fail_Daily_Run', {'type': 'Terminate', 'inputs': {'runStatus': 'Failed', 'runError': {'code': 'DAILY_REPORT_NOT_ACCEPTED', 'message': "@concat('Inspect worker run for ', outputs('Due_Publication_Date'), '. No automatic missed-day replay or cross-run duplicate check is configured.')"}}}))), 'runAfter': {'Invoke_Day_Worker': ALL}})))))
    trigger = {'Daily_0900_JST': {'type': 'Recurrence', 'recurrence': {'frequency': 'Day', 'interval': 1, 'timeZone': 'Tokyo Standard Time', 'startTime': "[parameters('firstScheduleLocalTime')]", 'schedule': {'hours': [9], 'minutes': [0]}}, 'runtimeConfiguration': {'concurrency': {'runs': 1}}}}
    return definition(result, {'FirstReportDate': {'type': 'String', 'defaultValue': "[parameters('firstReportDate')]"}}, trigger)


def workflow_resource(name: str, body: dict, parameters: dict, dependencies: list[str],
                      *, identity: bool = False, scheduled: bool = False) -> dict:
    resource = {
        "type": "Microsoft.Logic/workflows", "apiVersion": "2019-05-01",
        "name": f"[variables('{name}')]", "location": "[parameters('location')]",
        "dependsOn": dependencies,
        "properties": {
            "state": "[parameters('scheduleState')]" if scheduled else "Enabled",
            "definition": body,
            "parameters": {key: {"value": value} for key, value in parameters.items()},
        },
        "tags": {"workload": "NvdCriticalDaily", "runtimeCode": "none", "llm": "none"},
    }
    if identity:
        resource["identity"] = {"type": "SystemAssigned"}
    if not scheduled:
        # 0.0.0.0-0.0.0.0 = "Only other Logic Apps": direct REST/curl callers are rejected even with the SAS URL.
        resource["properties"]["accessControl"] = {
            "triggers": {"allowedCallerIpAddresses": [{"addressRange": "0.0.0.0-0.0.0.0"}]},
        }
    return resource




def build() -> dict:
    swagger = json.loads((ROOT / 'NvdCveApi.swagger.json').read_text(encoding='utf-8'))
    resources = [{'type': 'Microsoft.Web/customApis', 'apiVersion': '2016-06-01', 'name': "[variables('nvdApiName')]", 'location': "[parameters('location')]", 'properties': {'displayName': 'NVD Publication Pages', 'description': 'Complete publication-day pages; workflow-supplied secure header; no severity prefilter.', 'apiType': 'Rest', 'backendService': {'serviceUrl': 'https://services.nvd.nist.gov'}, 'swagger': swagger}}, {'type': 'Microsoft.Web/connections', 'apiVersion': '2016-06-01', 'kind': 'V1', 'name': "[variables('nvdConnectionName')]", 'location': "[parameters('location')]", 'dependsOn': ["[resourceId('Microsoft.Web/customApis', variables('nvdApiName'))]"], 'properties': {'displayName': 'NVD transport (workflow-supplied API key)', 'api': {'id': "[resourceId('Microsoft.Web/customApis', variables('nvdApiName'))]"}}}, {'type': 'Microsoft.Web/connections', 'apiVersion': '2016-06-01', 'kind': 'V1', 'condition': "[parameters('createOffice365Connection')]", 'name': "[variables('office365ConnectionName')]", 'location': "[parameters('location')]", 'properties': {'displayName': "[parameters('senderMailbox')]", 'api': {'id': "[subscriptionResourceId('Microsoft.Web/locations/managedApis', parameters('location'), 'office365')]"}}}, workflow_resource('formatterName', formatter_definition(swagger), {}, []), workflow_resource('workerName', worker_definition(swagger), {'$connections': {'nvd': {'connectionId': "[resourceId('Microsoft.Web/connections', variables('nvdConnectionName'))]", 'connectionName': "[variables('nvdConnectionName')]", 'id': "[resourceId('Microsoft.Web/customApis', variables('nvdApiName'))]"}, 'office365': {'connectionId': "[resourceId('Microsoft.Web/connections', variables('office365ConnectionName'))]", 'connectionName': "[variables('office365ConnectionName')]", 'id': "[subscriptionResourceId('Microsoft.Web/locations/managedApis', parameters('location'), 'office365')]"}}, 'NvdApiKey': "[parameters('nvdApiKey')]"}, ["[resourceId('Microsoft.Logic/workflows', variables('formatterName'))]", "[resourceId('Microsoft.Web/connections', variables('nvdConnectionName'))]", "[resourceId('Microsoft.Web/connections', variables('office365ConnectionName'))]"], identity=True), workflow_resource('schedulerName', scheduler_definition(), {}, ["[resourceId('Microsoft.Logic/workflows', variables('workerName'))]"], identity=True, scheduled=True)]
    for workflow in ('schedulerName', 'workerName', 'formatterName'):
        resources.append({'type': 'Microsoft.Insights/diagnosticSettings', 'apiVersion': '2021-05-01-preview', 'condition': "[not(empty(parameters('logAnalyticsWorkspaceId')))]", 'name': 'workflow-runtime', 'scope': f"[resourceId('Microsoft.Logic/workflows', variables('{workflow}'))]", 'dependsOn': [f"[resourceId('Microsoft.Logic/workflows', variables('{workflow}'))]"], 'properties': {'workspaceId': "[parameters('logAnalyticsWorkspaceId')]", 'logs': [{'category': 'WorkflowRuntime', 'enabled': True}]}})
    return {'$schema': 'https://schema.management.azure.com/schemas/2019-04-01/deploymentTemplate.json#', 'contentVersion': '2.0.0.0', 'metadata': {'description': 'Storage-free native Consumption Logic Apps with run-history and Log Analytics audit.', 'runtime': 'No customer Storage account, Python, JavaScript, Azure Functions, Integration Account or LLM.'}, 'parameters': {'namePrefix': {'type': 'string', 'defaultValue': 'nvdcriticaldaily', 'minLength': 3, 'maxLength': 40}, 'location': {'type': 'string', 'defaultValue': '[resourceGroup().location]'}, 'firstReportDate': {'type': 'string', 'minLength': 10, 'maxLength': 10, 'metadata': {'description': 'Earliest allowed manual publication date, not a persistent catch-up cursor.'}}, 'firstScheduleLocalTime': {'type': 'string', 'defaultValue': "[concat(dateTimeAdd(concat(utcNow('yyyy-MM-dd'), 'T00:00:00Z'), 'P1D', 'yyyy-MM-dd'), 'T08:00:00')]", 'metadata': {'description': 'Tokyo local YYYY-MM-DDT08:00:00 without Z/offset. Use a time before 09:00: a start time exactly at the 09:00 schedule instant skips that first occurrence.'}}, 'senderMailbox': {'type': 'string'}, 'recipientEmail': {'type': 'string'}, 'nvdApiKey': {'type': 'securestring', 'minLength': 16, 'metadata': {'description': 'Sets only worker SecureString NvdApiKey. No Key Vault.'}}, 'nvdPageSize': {'type': 'int', 'defaultValue': 200, 'minValue': 1, 'maxValue': 2000}, 'maxMailRequestBytes': {'type': 'int', 'defaultValue': 3000000, 'minValue': 1024, 'maxValue': 3500000}, 'scheduleState': {'type': 'string', 'defaultValue': 'Disabled', 'allowedValues': ['Disabled', 'Enabled']}, 'mailSendingEnabled': {'type': 'bool', 'defaultValue': False}, 'createOffice365Connection': {'type': 'bool', 'defaultValue': True, 'metadata': {'description': 'Create the Office 365 Outlook API connection. Redeploying may reset its authorization; set false after the first authorization.'}}, 'logAnalyticsWorkspaceId': {'type': 'string', 'defaultValue': '', 'metadata': {'description': 'Existing workspace resource ID; empty means run history only.'}}}, 'variables': {'schedulerName': "[concat(parameters('namePrefix'), '-scheduler')]", 'workerName': "[concat(parameters('namePrefix'), '-worker')]", 'formatterName': "[concat(parameters('namePrefix'), '-formatter')]", 'nvdApiName': "[concat(parameters('namePrefix'), '-nvd-api')]", 'nvdConnectionName': "[concat(parameters('namePrefix'), '-nvd-connection')]", 'office365ConnectionName': "[concat(parameters('namePrefix'), '-office365-connection')]"}, 'resources': resources, 'outputs': {'schedulerResourceId': {'type': 'string', 'value': "[resourceId('Microsoft.Logic/workflows', variables('schedulerName'))]"}, 'workerResourceId': {'type': 'string', 'value': "[resourceId('Microsoft.Logic/workflows', variables('workerName'))]"}, 'formatterResourceId': {'type': 'string', 'value': "[resourceId('Microsoft.Logic/workflows', variables('formatterName'))]"}, 'workerPrincipalId': {'type': 'string', 'value': "[reference(resourceId('Microsoft.Logic/workflows', variables('workerName')), '2019-05-01', 'Full').identity.principalId]"}, 'scheduleState': {'type': 'string', 'value': "[parameters('scheduleState')]"}, 'mailSendingEnabled': {'type': 'bool', 'value': "[parameters('mailSendingEnabled')]"}, 'logAnalyticsWorkspaceId': {'type': 'string', 'value': "[parameters('logAnalyticsWorkspaceId')]"}}}


def main() -> None:
    template = build()
    destination = ROOT / "azuredeploy.json"
    destination.write_text(json.dumps(template, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    for resource in template["resources"]:
        if resource["type"] == "Microsoft.Logic/workflows":
            suffix = resource["name"].split("'")[1].replace("Name", "")
            (ROOT / "workflows").mkdir(exist_ok=True)
            (ROOT / "workflows" / f"{suffix}.json").write_text(
                json.dumps(resource["properties"]["definition"], ensure_ascii=False, indent=2) + "\n",
                encoding="utf-8",
            )
    print(f"Generated self-contained ARM template: {destination}")


if __name__ == "__main__":
    main()
