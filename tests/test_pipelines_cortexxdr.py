import pytest
from sigma.collection import SigmaCollection
from sigma.backends.cortexxdr import CortexXDRBackend

@pytest.fixture
def cortexxdr_backend():
  return CortexXDRBackend()

def test_cortexxdr_windows_os_filter(cortexxdr_backend : CortexXDRBackend):
    assert cortexxdr_backend.convert(
        SigmaCollection.from_yaml("""
            title: Test
            status: test
            logsource:
                category: process_creation
                product: windows
            detection:
                sel:
                    Image: valueA
                condition: sel
        """)
    ) == ['dataset=xdr_data | filter (event_type = ENUM.PROCESS and event_sub_type = ENUM.PROCESS_START) and (agent_os_type = ENUM.AGENT_OS_WINDOWS) and (action_process_image_path = "valueA")']

def test_cortexxdr_linux_os_filter(cortexxdr_backend : CortexXDRBackend):
    assert cortexxdr_backend.convert(
        SigmaCollection.from_yaml("""
            title: Test
            status: test
            logsource:
                category: process_creation
                product: linux
            detection:
                sel:
                    Image: valueA
                condition: sel
        """)
    ) == ['dataset=xdr_data | filter (event_type = ENUM.PROCESS and event_sub_type = ENUM.PROCESS_START) and (agent_os_type = ENUM.AGENT_OS_LINUX) and (action_process_image_path = "valueA")']

def test_cortexxdr_osx_os_filter(cortexxdr_backend : CortexXDRBackend):
    assert cortexxdr_backend.convert(
        SigmaCollection.from_yaml("""
            title: Test
            status: test
            logsource:
                category: process_creation
                product: macos
            detection:
                sel:
                    Image: valueA
                condition: sel
        """)
    ) == ['dataset=xdr_data | filter (event_type = ENUM.PROCESS and event_sub_type = ENUM.PROCESS_START) and (agent_os_type = ENUM.AGENT_OS_MAC) and (action_process_image_path = "valueA")']

def test_cortexxdr_process_creation_mapping(cortexxdr_backend : CortexXDRBackend):
    assert cortexxdr_backend.convert(
        SigmaCollection.from_yaml("""
            title: Test
            status: test
            logsource:
                category: process_creation
                product: test_product
            detection:
                sel:
                    ProcessId: 12
                    Image: valueA
                    Product: bar foo
                    Company: foo foo
                    CommandLine: invoke-mimikatz
                    CurrentDirectory: /etc
                    User: administrator
                    IntegrityLevel: bar bar
                    md5: asdfasdfasdfasdfasdf
                    sha256: asdfasdfasdfasdfasdfasdfasdfasdf
                    ParentProcessId: 13
                    ParentImage: valueB
                    ParentCommandLine: Get-Path
                condition: sel
        """)
    ) == ['dataset=xdr_data | filter (event_type = ENUM.PROCESS and event_sub_type = ENUM.PROCESS_START) and (action_process_os_pid = "12" and' + 
          'action_process_image_path = "valueA" and action_process_signature_product = "bar foo" and action_process_signature_vendor = "foo foo" and' + 
          'action_process_image_command_line = "invoke-mimikatz" and action_process_cwd = "/etc" and action_process_username = "administrator" and ' + 
          'action_process_integrity_level = "bar bar" and action_process_image_md5 = "asdfasdfasdfasdfasdf" and ' + 
          'action_process_image_sha256 = "asdfasdfasdfasdfasdfasdfasdfasdf" and actor_process_os_pid = "13" and actor_process_image_command_line = "Get-Path")']

def test_cortexxdr_file_mapping(cortexxdr_backend : CortexXDRBackend):
    assert cortexxdr_backend.convert(
        SigmaCollection.from_yaml("""
            title: Test
            status: test
            logsource:
                category: file_event
                product: test_product
            detection:
                sel:
                    Image: valueA
                    CommandLine: invoke-mimikatz
                    ParentImage: valueB
                    ParentCommandLine: Get-Path
                    TargetFilename: foo bar
                    SourceFilename: bar foo
                condition: sel
        """)
    ) == ['dataset=xdr_data | filter (event_type = ENUM.FILE) and (actor_process_image_path = "valueA" and ' + 
          'actor_Process_image_command_line = "invoke-mimikatz" and causality_actor_process_image_path = "valueB" and ' + 
          'causality_actor_process_command_line = "Get-Path" and action_file_name = "foo bar" and action_file_previous_file_name = "bar foo")']

def test_cortexxdr_image_load_mapping(cortexxdr_backend : CortexXDRBackend):
    assert cortexxdr_backend.convert(
        SigmaCollection.from_yaml("""
            title: Test
            status: test
            logsource:
                category: image_load
                product: test_product
            detection:
                sel:
                    Image: valueA
                    CommandLine: invoke-mimikatz
                    ParentImage: valueB
                    ParentCommandLine: Get-Path
                    ImageLoaded: foo bar
                    md5: asdfasdfasdf
                    sha256: asdfasdfasdfasdf
                condition: sel
        """)
    ) == ['dataset=xdr_data | filter (event_type = ENUM.LOAD_IMAGE) and (actor_process_image_path = "valueA" and' + 
          'actor_process_image_command_line = "invoke-mimikatz" and causality_actor_process_image_path = "valueB" and ' + 
          'causality_actor_process_command_line = "Get-Path" and action_module_path = "foo bar" and action_module_md5 = "asdfasdf" and ' + 
          'action_module_sha256 = "asdfasdfasdfasdf")']

def test_cortexxdr_registry_mapping(cortexxdr_backend : CortexXDRBackend):
    assert cortexxdr_backend.convert(
        SigmaCollection.from_yaml("""
            title: Test
            status: test
            logsource:
                category: registry_event
                product: test_product
            detection:
                sel:
                    Image: valueA
                    CommandLine: invoke-mimikatz
                    ParentImage: valueB
                    ParentCommandLine: Get-Path
                    TargetObject: foo bar
                    Details: bar foo
                condition: sel
        """)
    ) == ['dataset=xdr_data | filter (event_type = ENUM.REGISTRY) and (actor_process_image_path = "valueA" and ' + 
          'actor_process_image_command_line = "invoke-mimikatz" and causality_actor_process_image_path = "valueB" and' + 
          'causality_actor_process_command_line = "Get-Path" and action_registry_key_name = "foo bar" and ' + 
          '(action_registry_value_name = "bar foo" or action_registry_data = "bar foo"))']

def test_cortexxdr_network_mapping(cortexxdr_backend : CortexXDRBackend):
    assert cortexxdr_backend.convert(
        SigmaCollection.from_yaml("""
            title: Test
            status: test
            logsource:
                category: network_connection
                product: test_product
            detection:
                sel:
                    Image: valueA
                    CommandLine: invoke-mimikatz
                    ParentImage: valueB
                    ParentCommandLine: Get-Path
                    DestinationPort: 445
                    DestinationIp: 0.0.0.0
                    User: administrator
                    SourcePort: 135
                    SourceIp: 1.1.1.1
                    Protocol: udp
                    dst_ip: 2.2.2.2
                    dst_port: 80
                    src_ip: 3.3.3.3
                    src_port: 8080
                condition: sel
        """)
    ) == ['dataset=xdr_data | filter event_type = ENUM.NETWORK and (actor_process_image_path = "valueA" and ' + 
          'actor_process_image_command_line = "invoke-mimikatz" and causality_actor_process_image_path = "valueB" and ' + 
          'causality_actor_process_command_line = "Get-Path" and (action_local_port = "445" or action_remote_port = "445) and ' +
          '(action_local_ip = "0.0.0.0" or action_remote_ip = "0.0.0.0") and action_username = "administrator" and ' + 
          '(action_local_port = "135" or action_remote_port = "135) and (action_local_ip = "1.1.1.1" or action_remote_ip = "1.1.1.1") and ' + 
          'action_network_protocol = "udp" and (action_local_ip = "2.2.2.2" or action_remote_ip = "2.2.2.2") and ' + 
          '(action_local_port = "80" or action_remote_port = "80") and (action_local_ip = "3.3.3.3" or action_remote_ip = "3.3.3.3") and ' + 
          '(action_local_port = "8080" or action_remove_port = "8080))']

def test_cortexxdr_unsupported_rule_type(cortexxdr_backend : CortexXDRBackend):
  with pytest.raises(ValueError):
    cortexxdr_backend.convert(
        SigmaCollection.from_yaml("""
            title: Test
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                sel:
                    Image: valueA
                    CommandLine: invoke-mimikatz
                    ParentImage: valueB
                    ParentCommandLine: Get-Path
                condition: sel
        """)
    )

def test_cortexxdr_unsupported_field_name(cortexxdr_backend : CortexXDRBackend):
  with pytest.raises(ValueError):
    cortexxdr_backend.convert(
        SigmaCollection.from_yaml("""
            title: Test
            status: test
            logsource:
                category: process_creation
                product: test_product
            detection:
                sel:
                    FOO: bar
                condition: sel
        """)
    )