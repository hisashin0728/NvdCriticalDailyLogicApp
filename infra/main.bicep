targetScope = 'subscription'

param resourceGroupName string
param location string
param createResourceGroup bool = true
param namePrefix string = 'nvdcriticaldaily'
param firstReportDate string
param senderMailbox string
param recipientEmail string

@secure()
param nvdApiKey string

param logAnalyticsWorkspaceId string = ''

param createOffice365Connection bool = true

resource group 'Microsoft.Resources/resourceGroups@2025-04-01' = if (createResourceGroup) {
  name: resourceGroupName
  location: location
  tags: {
    workload: 'NvdCriticalDaily'
    deploymentPhase: 'inactive-infrastructure'
  }
}

// Retain the existing ARM implementation; preview RG creation and app resources together.
module application '../azuredeploy.json' = {
  name: '${namePrefix}-resources'
  scope: resourceGroup(resourceGroupName)
  dependsOn: [
    group
  ]
  params: {
    namePrefix: namePrefix
    location: location
    firstReportDate: firstReportDate
    senderMailbox: senderMailbox
    recipientEmail: recipientEmail
    nvdApiKey: nvdApiKey
    nvdPageSize: 200
    maxMailRequestBytes: 3000000
    scheduleState: 'Disabled'
    mailSendingEnabled: false
    logAnalyticsWorkspaceId: logAnalyticsWorkspaceId
    createOffice365Connection: createOffice365Connection
  }
}

output resourceGroupId string = subscriptionResourceId('Microsoft.Resources/resourceGroups', resourceGroupName)
output schedulerResourceId string = application.outputs.schedulerResourceId
output workerResourceId string = application.outputs.workerResourceId
output formatterResourceId string = application.outputs.formatterResourceId
output workerPrincipalId string = application.outputs.workerPrincipalId
output logAnalyticsWorkspaceId string = application.outputs.logAnalyticsWorkspaceId
output scheduleState string = application.outputs.scheduleState
output mailSendingEnabled bool = application.outputs.mailSendingEnabled
