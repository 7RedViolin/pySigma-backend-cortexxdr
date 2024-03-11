from typing import Union
from sigma.pipelines.common import logsource_windows, windows_logsource_mapping
from sigma.processing.transformations import ConditionTransformation, AddConditionTransformation, FieldMappingTransformation, DetectionItemFailureTransformation, RuleFailureTransformation, ChangeLogsourceTransformation
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

    translation_dict = {
        'process_creation':{
            "ProcessId":"action_process_os_pid",
            "Image":"action_process_image_path",
            "Product":"action_process_signature_product",
            "Company":"action_process_signature_vendor",
            "CommandLine":"action_process_image_command_line",
            "CurrentDirectory":"action_process_cwd",
            "User":"action_process_username",
            "IntegrityLevel":"action_process_integrity_level",
            "md5":"action_process_image_md5",
            "sha256":"action_process_image_sha256",
            "ParentProcessId":"actor_process_os_pid",
            "ParentImage":"actor_process_image_path",
            "ParentCommandLine":"actor_process_image_command_line",
        },
        'file_activity':{
            'Image': 'actor_process_image_path',
            'CommandLine': 'actor_process_image_command_line',
            'ParentImage': 'causality_actor_process_image_path',
            'ParentCommandLine': 'causality_actor_process_command_line',
            'TargetFilename': 'action_file_name',
            'SourceFilename': 'action_file_previous_file_name'
        },
        'image_load':{
            'Image': 'actor_process_image_path',
            'CommandLine': 'actor_process_image_command_line',
            'ParentImage': 'causality_actor_process_image_path',
            'ParentCommandLine': 'causality_actor_process_command_line',
            'ImageLoaded': 'action_module_path',
            'md5': 'action_module_md5',
            'sha256': 'action_module_sha256',
        },
        "registry":{
            'Image': 'actor_process_image_path',
            'CommandLine': 'actor_process_image_command_line',
            'ParentImage': 'causality_actor_process_image_path',
            'ParentCommandLine': 'causality_actor_process_command_line',
            'TargetObject': 'action_registry_key_name',
            'Details': ['action_registry_value_name', 'action_registry_data']
        },
        'network':{
            'Image': 'actor_process_image_path',
            'CommandLine': 'actor_process_image_command_line',
            'ParentImage': 'causality_actor_process_image_path',
            'ParentCommandLine': 'causality_actor_process_command_line',
            'DestinationPort': ['action_local_port', 'action_remote_port'],
            'DestinationIp': ['action_local_ip', 'action_remote_ip'],
            'User': 'action_username',
            'SourcePort': ['action_local_port', 'action_remote_port'],
            'SourceIp': ['action_local_ip', 'action_remote_ip'],
            'Protocol': 'action_network_protocol',
            'dst_ip': ['action_local_ip', 'action_remote_ip'],
            'dst_port': ['action_local_port', 'action_remote_port'],
            'src_ip': ['action_local_ip', 'action_remote_ip'],
            'src_port': ['action_local_port', 'action_remote_port'],
        }
    }

    os_filter = [
        # Windows
        ProcessingItem(
            identifier="cortexxdr_windows_os",
            transformation=AddConditionTransformation({
                "agent_os_type": "ENUM.AGENT_OS_WINDOWS"
            }),
            rule_conditions=[
                LogsourceCondition(product="windows")
            ]
        ),
        # Linux
        ProcessingItem(
            identifier="cortexxdr_linux_os",
            transformation=AddConditionTransformation({
                "agent_os_type": "ENUM.AGENT_OS_LINUX"
            }),
            rule_conditions=[
                LogsourceCondition(product="linux")
            ]
        ),
        # macOS
        ProcessingItem(
            identifier="cortexxdr_macos_os",
            transformation=AddConditionTransformation({
                "agent_os_type": "ENUM.AGENT_OS_MAC"
            }),
            rule_conditions=[
                LogsourceCondition(product="macos")
            ]
        )
    ]

    event_type_filters = [
        ProcessingItem(
            identifier="cortex_process_creation_eventtype",
            transformation=AddConditionTransformation({
                "event_type": "ENUM.PROCESS",
                "event_sub_type": "ENUM.PROCESS_START"
            }),
            rule_conditions = [
                LogsourceCondition(category="process_creation")
            ]
        ),
        ProcessingItem(
            identifier="cortex_file_activity_eventtype",
            transformation=AddConditionTransformation({
                "event_type":"ENUM.FILE"
            }),
            rule_condition_linking=any,
            rule_conditions=[
                LogsourceCondition(category="file_change"),
                LogsourceCondition(category="file_rename"),
                LogsourceCondition(category="file_delete"),
                LogsourceCondition(category="file_event")
            ]
        ),
        ProcessingItem(
            identifier="cortex_image_load_eventtype",
            transformation=AddConditionTransformation({
                "event_type":"ENUM.LOAD_IMAGE"
            }),
            rule_conditions=[
                LogsourceCondition(category="image_load")
            ]
        ),
        ProcessingItem(
            identifier="cortex_registry_eventtype",
            transformation=AddConditionTransformation({
                "event_type":"ENUM.REGISTRY"
            }),
            rule_condition_linking=any,
            rule_conditions=[
                LogsourceCondition(category="registry_add"),
                LogsourceCondition(category="registry_delete"),
                LogsourceCondition(category="registry_event"),
                LogsourceCondition(category="registry_set")
            ]
        ),
        ProcessingItem(
            identifier="cortex_network_eventtype",
            transformation=AddConditionTransformation({
                "event_type":"ENUM.NETWORK"
            }),
            rule_condition_linking=any,
            rule_conditions=[
                LogsourceCondition(category="network_connection"),
                LogsourceCondition(category="firewall")
            ]
        )
    ]

    field_mappings = [
        ProcessingItem(
            identifier="cortex_process_creation_fieldmapping",
            transformation=FieldMappingTransformation(translation_dict['process_creation']),
            rule_conditions=[
                LogsourceCondition(category="process_creation")
            ]
        ),
        ProcessingItem(
            identifier="cortex_file_activity_fieldmapping",
            transformation=FieldMappingTransformation(translation_dict['file_activity']),
            rule_condition_linking=any,
            rule_conditions=[
                LogsourceCondition(category="file_change"),
                LogsourceCondition(category="file_rename"),
                LogsourceCondition(category="file_delete"),
                LogsourceCondition(category="file_event")
            ]
        ),
        ProcessingItem(
            identifier="cortex_image_load_fieldmapping",
            transformation=FieldMappingTransformation(translation_dict['image_load']),
            rule_conditions=[
                LogsourceCondition(category="image_load")
            ]
        ),
        ProcessingItem(
            identifier="cortex_registry_fieldmapping",
            transformation=FieldMappingTransformation(translation_dict['registry']),
            rule_condition_linking=any,
            rule_conditions=[
                LogsourceCondition(category="registry_add"),
                LogsourceCondition(category="registry_delete"),
                LogsourceCondition(category="registry_event"),
                LogsourceCondition(category="registry_set")
            ]
        ),
        ProcessingItem(
            identifier="cortex_network_fieldmapping",
            transformation=FieldMappingTransformation(translation_dict['network']),
            rule_condition_linking=any,
            rule_conditions=[
                LogsourceCondition(category="network_connection"),
                LogsourceCondition(category="firewall")
            ]
        )
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
                LogsourceCondition(category="process_creation"),
                LogsourceCondition(category="file_change"),
                LogsourceCondition(category="file_rename"),
                LogsourceCondition(category="file_delete"),
                LogsourceCondition(category="file_event"),
                LogsourceCondition(category="image_load"),
                LogsourceCondition(category="registry_add"),
                LogsourceCondition(category="registry_delete"),
                LogsourceCondition(category="registry_event"),
                LogsourceCondition(category="registry_set"),
                LogsourceCondition(category="network_connection"),
                LogsourceCondition(category="firewall")
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

    unsupported_field_name = [
        ProcessingItem(
            identifier='cortex_fail_field_not_supported',
            transformation=InvalidFieldTransformation("This pipeline only supports the following fields:\n{" + 
            '}, {'.join(sorted(set(sum([list(translation_dict[x].keys()) for x in translation_dict.keys()],[])))) + '}'),
            field_name_conditions=[
                ExcludeFieldCondition(fields=list(set(sum([list(translation_dict[x].keys()) for x in translation_dict.keys()],[]))))
            ]
        )
    ]

    return ProcessingPipeline(
        name="CortexXDR pipeline",
        priority=50,
        items = [
            *unsupported_field_name,
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