from typing import Union
from sigma.pipelines.common import logsource_windows, windows_logsource_mapping
from sigma.processing.transformations import ConditionTransformation, AddConditionTransformation, FieldMappingTransformation, DetectionItemFailureTransformation, RuleFailureTransformation, ChangeLogsourceTransformation, SetStateTransformation
from sigma.processing.conditions import LogsourceCondition, ExcludeFieldCondition, RuleProcessingItemAppliedCondition
from sigma.processing.pipeline import ProcessingItem, ProcessingPipeline
from sigma.processing.postprocessing import QueryPostprocessingTransformation
from sigma.rule import SigmaDetectionItem, SigmaDetection, SigmaRule
from sigma.exceptions import SigmaTransformationError
import re
import json

class InvalidFieldTransformation(DetectionItemFailureTransformation):
    """
    Overrides the apply_detection_item() method from DetectionItemFailureTransformation to also include the field name
    in the error message
    """

    def apply_detection_item(self, detection_item: SigmaDetectionItem) -> None:
        field_name = detection_item.field
        self.message = f"Invalid SigmaDetectionItem field name encountered: {field_name}. " + self.message
        raise SigmaTransformationError(self.message)

## Custom QueryPostprocessingTransformation to convert string values in IntegrityLevel field to integer range, if applicable
class ReplaceIntegrityLevelQueryTransformation(QueryPostprocessingTransformation):
    """Replace query part specified by regular expression with a given string."""

    def apply(
        self, pipeline: "sigma.processing.pipeline.ProcessingPipeline", rule: SigmaRule, query: Union[str, dict]
    ) -> Union[str, dict]:

        if isinstance(query, dict):
            output_type = 'json'
            query = json.dumps(query)
        else:
            output_type = 'default'

        self.identifier = 'replace_integrity_thing'
        field_name = 'action_process_integrity_level'

        super().apply(pipeline, rule, query)

        integrity_level_ranges ={
            'UNTRUSTED': f'{field_name} lt 4096',
            'LOW': f'({field_name} gte 4096 and {field_name} lt 8192)',
            'MEDIUM': f'({field_name} gte 8192 and {field_name} lt 12288)',
            'HIGH': f'({field_name} gte 12288 and {field_name} lt 16384)',
            'SYSTEM': f'{field_name} gte 16384'
        }

        single_pattern = '(?i)' + field_name + ' = "(' + '|'.join(integrity_level_ranges) + ')"'
        multi_pattern = '(?i)' + field_name + " in \\(((\"(" + '|'.join(integrity_level_ranges) + ")\")((, )*)){1,}\\)"

        if re.search(single_pattern, query): # for single value
            for level in integrity_level_ranges.items():
                query = re.sub(f'(?i){field_name} = "{level[0]}"', level[1], query)

        while re.search(multi_pattern, query): # for multiple values
            matches = re.search(multi_pattern, query)
            target_string = matches.group(0)

            values = (re.sub(f"(?i){field_name} in \\(", '', target_string)).replace(')', '').replace('"', '').split(',')
            replacement_values = []

            for value in values:
                if value.strip().upper() in integrity_level_ranges.keys():
                    replacement_values.append(integrity_level_ranges[value.strip().upper()])

            replacement_string = '(' + ' or '.join(replacement_values) + ')'
            query = query.replace(target_string, replacement_string)

        if output_type == 'json':
            query = json.loads(query)

        return query, True


def CortexXDR_pipeline() -> ProcessingPipeline:

    logsource_category_to_event_type = {
        'process_creation':{
            "event_type": "ENUM.PROCESS",
            "event_sub_type": "ENUM.PROCESS_START"
        },
        "file_change": {
            "event_type":"ENUM.FILE"
        },
        "file_rename": {
            "event_type":"ENUM.FILE",
            'event_sub_type': 'ENUM.FILE_RENAME'
        },
        "file_delete": {
            "event_type":"ENUM.FILE",
            'event_sub_type': 'ENUM.FILE_REMOVE'
        },
        "file_event":{
            "event_type":"ENUM.FILE"
        },
        'image_load':{
            "event_type":"ENUM.LOAD_IMAGE"
        },
        "registry_add":{
            "event_type":"ENUM.REGISTRY",
            'event_sub_type': 'ENUM.REGISTRY_CREATE_KEY'
        },
        "registry_delete":{
            "event_type":"ENUM.REGISTRY",
            'event_sub_type': ['ENUM.REGISTRY_DELETE_KEY', 'ENUM.REGISTRY_DELETE_VALUE']
        },
        "registry_event":{
            "event_type":"ENUM.REGISTRY"
        },
        "registry_set":{
            "event_type":"ENUM.REGISTRY",
            'event_sub_type': 'ENUM.REGISTRY_SET_VALUE'
        },
        "network_connection": {
            "event_type":"ENUM.NETWORK"
        },
        "firewall":{
            "event_type":"ENUM.NETWORK"
        }
    }

    generic_translation_dict = {
        'User': 'actor_effective_username',
        'CommandLine': 'actor_process_image_command_line',
        'Image': 'actor_process_image_path',
        "LogonId": "actor_process_logon_id",
        "Product": "actor_process_signature_product",
        "Company": "actor_process_signature_vendor",
        "IntegrityLevel": "actor_process_integrity_level",
        'CurrentDirectory': 'actor_process_cwd',
        'ProcessId': 'actor_process_os_id',
        'ParentProcessId': 'causality_actor_process_os_id',
        'ParentCommandLine': 'causality_actor_process_command_line',
        'ParentImage': 'causality_actor_process_image_path',
        "ParentUser": "causality_actor_effective_username",
        'ParentIntegrityLevel': 'causality_actor_process_integrity_level',
        'ParentLogonId': 'causality_actor_process_logon_id',
        'ParentProduct': 'causality_actor_process_signature_product',
        'ParentCompany': 'causality_actor_process_signature_vendor'
        #'ProcessGuid': ?,
        #'ParentProcessGuid': ?,
        #'FileVersion': ?,
        #'Description': ?,
        #'OriginalFileName': ?,
        #'EventType': ?,
    }

    translation_dict = {
        'process':{
            'index': {
                'name': 'xdr_process',
                'type': 'preset'
            },
            'category': ['process_creation'],
            'fields':{
                "User":"action_process_username",
                "CommandLine":"action_process_image_command_line",
                "Image":"action_process_image_path",
                "LogonId": "action_process_logon_id",
                "Product":"action_process_signature_product",
                "Company":"action_process_signature_vendor",
                "IntegrityLevel":"action_process_integrity_level",
                "CurrentDirectory":"action_process_cwd",
                "ProcessId":"action_process_os_pid",
                "ParentProcessId":"actor_process_os_pid",
                "ParentCommandLine":"actor_process_image_command_line",
                "ParentImage":"actor_process_image_path",
                "ParentUser": "actor_effective_username",
                'ParentIntegrityLevel': 'actor_process_integrity_level',
                'ParentLogonId': 'actor_process_logon_id',
                'ParentProduct': 'actor_process_signature_product',
                'ParentCompany': 'actor_process_signature_vendor',
                "md5":"action_process_image_md5",
                "sha256":"action_process_image_sha256",
                #"ProcessGuid": ?,
                #'ParentProcessGuid': ?,
                #"FileVersion": ?,
                #"Description": ?,
                #"OriginalFileName": ?,
                #"Hashes": ?,
                #'EventType': ?,
                #"LogonGuid": ?,
                #"TerminalSessionId": ?,
                #"sha1": ?,
            }
        },
        'file':{
            'index': {
                'name': 'xdr_file',
                'type': 'preset'
            },
            'category': ['file_change','file_rename','file_delete','file_event'],
            'fields':{
                **generic_translation_dict,
                'TargetFilename': 'action_file_name',
                'SourceFilename': 'action_file_previous_file_name',
                #'sha1': ?,
                #'sha256': ?,
                #'md5': ?,
                #'Hashes': ?,
                #'CreationUtcTime': ?
            }
        },
        'image_load':{
            'index': {
                'name': 'xdr_image_load',
                'type': 'preset'
            },
            'category': ['image_load'],
            'fields':{
                **generic_translation_dict,
                'ImageLoaded': 'action_module_path',
                'md5': 'action_module_md5',
                'sha256': 'action_module_sha256',
                #'sha1': ?,
                #'Signed': ?,
                #'Signature': ?,
                #'SignatureStatus': ?
            }
        },
        "registry":{
            'index': {
                'name': 'xdr_registry',
                'type': 'preset'
            },
            'category': ['registry_add', 'registry_delete', 'registry_event', 'registry_set'],
            'fields': {
                **generic_translation_dict,
                'TargetObject': 'action_registry_key_name',
                'Details': ['action_registry_value_name', 'action_registry_data'],
                #'NewName': ?,
            }
        },
        'network':{
            'index': {
                'name': 'network_story', # or xdr_agent_network - not sure the difference
                'type': 'preset'
            },
            'category': ['network_connection','firewall'],
            'fields': {
                **generic_translation_dict,
                # Have to have local/remote like this because direction isn't defined that I can tell
                'DestinationPort': ['action_local_port', 'action_remote_port'],
                'DestinationIp': ['action_local_ip', 'action_remote_ip'],
                'SourcePort': ['action_local_port', 'action_remote_port'],
                'SourceIp': ['action_local_ip', 'action_remote_ip'],
                'Protocol': 'action_network_protocol',
                'dst_ip': ['action_local_ip', 'action_remote_ip'],
                'dst_port': ['action_local_port', 'action_remote_port'],
                'src_ip': ['action_local_ip', 'action_remote_ip'],
                'src_port': ['action_local_port', 'action_remote_port'],
                'DestinationHostname': 'action_external_hostname',
                'SourceHostname': 'agent_hostname',
                #'Initiated': ?,
                #'SourceIsIpv6': ?,
                #'SourcePortName': ?,
                #'DestinationIsIpv6': ?,
                #'DestinationPortName': ?
            }
        }
    }

    os_translation_dict = {
        'windows':{ 'agent_os_type': 'ENUM.AGENT_OS_WINDOWS' },
        'linux':{ 'agent_os_type': 'ENUM.AGENT_OS_LINUX' },
        'macos':{ 'agent_os_type': 'ENUM.AGENT_OS_MAC' }
    }

    os_filter = [
        ProcessingItem(
            identifier=f"cortexxdr_{os_name}_os",
            transformation=AddConditionTransformation(translation_value),
            rule_conditions=[
                LogsourceCondition(product=os_name)
            ]
        )
        for os_name, translation_value in os_translation_dict.items()
    ]

    event_type_filters = [
        ProcessingItem(
            identifier=f"cortex_{event_type}_eventtype",
            transformation=AddConditionTransformation(translation_value),
            rule_conditions = [
                LogsourceCondition(category=event_type)
            ]
        )
        for event_type, translation_value in logsource_category_to_event_type.items()
    ]

    dataset_preset_configuration = [
        ProcessingItem(
            identifier=f"cortex_dataset_preset_{activity_type}_config",
            transformation=SetStateTransformation('dataset_preset', details['index']['type'] + '::' + details['index']['name']),
            rule_conditions=[
                LogsourceCondition(category=category)
                for category in details['category']
            ],
            rule_condition_linking=any
        )
        for activity_type, details in translation_dict.items()
    ]

    field_mappings = [
        ProcessingItem(
            identifier=f"cortex_{activity_type}_fieldmapping",
            transformation=FieldMappingTransformation(details['fields']),
            rule_conditions=[
                LogsourceCondition(category=category)
                for category in details['category']
            ],
            rule_condition_linking=any
        )
        for activity_type, details in translation_dict.items()
    ]

    change_logsource_info = [
        # Add service to be SentinelOne for pretty much everything
        ProcessingItem(
            identifier="cortex_logsource",
            transformation=ChangeLogsourceTransformation(
                service="cortex"
            ),
            rule_condition_linking=any,
            rule_conditions=[
                LogsourceCondition(category=category)
                for category in logsource_category_to_event_type.keys()
            ]
        ),
    ]

    unsupported_rule_types = [
        # Show error if unsupported option
        ProcessingItem(
            identifier="cortex_fail_rule_not_supported",
            rule_condition_linking=any,
            transformation=RuleFailureTransformation("Rule type not yet supported by the Cortex XDR Sigma backend"),
            rule_condition_negation=True,
            rule_conditions=[
                RuleProcessingItemAppliedCondition("cortex_logsource")
            ]
        )
    ]
    
    unsupported_field_name_by_category = [
        ProcessingItem(
            identifier=f'cortex_fail_field_not_supported_{activity_type}',
            transformation=InvalidFieldTransformation("This pipeline only supports the following fields for " + activity_type + " activity:\n{" + 
            '}, {'.join(details['fields'].keys()) + '}'),
            field_name_conditions=[
                ExcludeFieldCondition(fields=details['fields'].keys())
            ],
            rule_conditions=[
                LogsourceCondition(category=category)
                for category in details['category']
            ],
            rule_condition_linking=any
        )
        for activity_type, details in translation_dict.items()
    ]

    return ProcessingPipeline(
        name="CortexXDR pipeline",
        priority=50,
        items = [
            *unsupported_field_name_by_category,
            *dataset_preset_configuration,
            *os_filter, 
            *event_type_filters,
            *field_mappings,
            *change_logsource_info,
            *unsupported_rule_types,
        ],
        postprocessing_items=[
            ReplaceIntegrityLevelQueryTransformation(),
        ],
    )