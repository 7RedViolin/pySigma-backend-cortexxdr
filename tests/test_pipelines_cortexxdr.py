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
    ) == ['preset=xdr_process | filter (event_type = ENUM.PROCESS and event_sub_type = ENUM.PROCESS_START) and (agent_os_type = ENUM.AGENT_OS_WINDOWS and action_process_image_path = "valueA")']

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
    ) == ['preset=xdr_process | filter (event_type = ENUM.PROCESS and event_sub_type = ENUM.PROCESS_START) and (agent_os_type = ENUM.AGENT_OS_LINUX and action_process_image_path = "valueA")']

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
    ) == ['preset=xdr_process | filter (event_type = ENUM.PROCESS and event_sub_type = ENUM.PROCESS_START) and (agent_os_type = ENUM.AGENT_OS_MAC and action_process_image_path = "valueA")']

def test_cortexxdr_integrity_levels_filter_single(cortexxdr_backend: CortexXDRBackend):
    assert cortexxdr_backend.convert(
        SigmaCollection.from_yaml("""
            title: Test
            status: test
            logsource:
                category: process_creation
                product: windows
            detection:
                sel:
                    IntegrityLevel: LOW
                condition: sel
        """)
    ) == ['preset=xdr_process | filter (event_type = ENUM.PROCESS and event_sub_type = ENUM.PROCESS_START) and (agent_os_type = ENUM.AGENT_OS_WINDOWS and (action_process_integrity_level gte 4096 and action_process_integrity_level lt 8192))']

def test_cortexxdr_integrity_levels_filter_multiple(cortexxdr_backend: CortexXDRBackend):
    assert cortexxdr_backend.convert(
        SigmaCollection.from_yaml("""
            title: Test
            status: test
            logsource:
                category: process_creation
                product: windows
            detection:
                sel:
                    IntegrityLevel:
                    - LOW
                    - HIGH
                condition: sel
        """)
    ) == ['preset=xdr_process | filter (event_type = ENUM.PROCESS and event_sub_type = ENUM.PROCESS_START) and (agent_os_type = ENUM.AGENT_OS_WINDOWS and (((action_process_integrity_level gte 4096 and action_process_integrity_level lt 8192) or (action_process_integrity_level gte 12288 and action_process_integrity_level lt 16384))))']

def test_cortexxdr_generic_translation_mapping(cortexxdr_backend: CortexXDRBackend):
    assert cortexxdr_backend.convert(
        SigmaCollection.from_yaml("""
            title: Test
            status: test
            logsource:
                category: file_event
                product: test_product
            detection:
                sel:
                    User: admin
                    CommandLine: cmdline /field=value,
                    Image: cmd.exe,
                    LogonId: logon_id_text,
                    Product: Product Name,
                    Company: Company Name
                    IntegrityLevel: High,
                    CurrentDirectory: /current/dir/value,
                    ProcessId: 1,
                    ParentProcessId: 2,
                    ParentCommandLine: cmdline_parent /field1=value1,
                    ParentImage: explorer.exe,
                    ParentUser: guest,
                    ParentIntegrityLevel: Medium,
                    ParentLogonId: logon_id_text_1,
                    ParentProduct: Parent Product Name,
                    ParentCompany: Parent Company Name
                condition: sel
        """)
    ) == ['preset=xdr_file | filter event_type = ENUM.FILE and (actor_effective_username = "admin" and actor_process_image_command_line = "cmdline /field=value," and actor_process_image_path = "cmd.exe," and actor_process_logon_id = "logon_id_text," and actor_process_signature_product = "Product Name," and actor_process_signature_vendor = "Company Name" and actor_process_integrity_level = "High," and actor_process_cwd = "/current/dir/value," and actor_process_os_id = "1," and causality_actor_process_os_id = "2," and causality_actor_process_command_line = "cmdline_parent /field1=value1," and causality_actor_process_image_path = "explorer.exe," and causality_actor_effective_username = "guest," and causality_actor_process_integrity_level = "Medium," and causality_actor_process_logon_id = "logon_id_text_1," and causality_actor_process_signature_product = "Parent Product Name," and causality_actor_process_signature_vendor = "Parent Company Name")']

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
                    User: admin,
                    CommandLine: cmdline /field=value,
                    Image: cmd.exe,
                    LogonId: logon_id_here,
                    Product: Product Name,
                    Company: Company Name,
                    IntegrityLevel: High,
                    CurrentDirectory: /current/working/directory,
                    ProcessId: 1,
                    ParentProcessId: 2,
                    ParentCommandLine: cmdline2 /field1=value1,
                    ParentImage: explorer.exe,
                    ParentUser: guest,
                    ParentIntegrityLevel: Low,
                    ParentLogonId: logon_id_here_parent,
                    ParentProduct: Parent Product Name,
                    ParentCompany: Parent Company Name,
                    md5: md5md5md5md5,
                    sha256: sha256sha256sha256
                condition: sel
        """)
    ) == ['preset=xdr_process | filter (event_type = ENUM.PROCESS and event_sub_type = ENUM.PROCESS_START) and (action_process_username = "admin," and action_process_image_command_line = "cmdline /field=value," and action_process_image_path = "cmd.exe," and action_process_logon_id = "logon_id_here," and action_process_signature_product = "Product Name," and action_process_signature_vendor = "Company Name," and action_process_integrity_level = "High," and action_process_cwd = "/current/working/directory," and action_process_os_pid = "1," and actor_process_os_pid = "2," and actor_process_image_command_line = "cmdline2 /field1=value1," and actor_process_image_path = "explorer.exe," and actor_effective_username = "guest," and actor_process_integrity_level = "Low," and actor_process_logon_id = "logon_id_here_parent," and actor_process_signature_product = "Parent Product Name," and actor_process_signature_vendor = "Parent Company Name," and action_process_image_md5 = "md5md5md5md5," and action_process_image_sha256 = "sha256sha256sha256")']

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
                    TargetFilename: foo bar
                    SourceFilename: bar foo
                condition: sel
        """)
    ) == ['preset=xdr_file | filter event_type = ENUM.FILE and (action_file_name = "foo bar" and action_file_previous_file_name = "bar foo")']

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
                    ImageLoaded: foo bar
                    md5: asdfasdfasdf
                    sha256: qwerqwerqwer
                condition: sel
        """)
    ) == ['preset=xdr_image_load | filter event_type = ENUM.LOAD_IMAGE and (action_module_path = "foo bar" and action_module_md5 = "asdfasdfasdf" and ' + 
          'action_module_sha256 = "qwerqwerqwer")']

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
                    TargetObject: foo bar
                    Details: bar foo
                condition: sel
        """)
    ) == ['preset=xdr_registry | filter event_type = ENUM.REGISTRY and (action_registry_key_name = "foo bar" and ' + 
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
                    SourcePort: 135
                    SourceIp: 1.1.1.1
                    Protocol: udp
                    dst_ip: 2.2.2.2
                    dst_port: 80
                    src_ip: 3.3.3.3
                    src_port: 8080
                condition: sel
        """)
    ) == ['preset=network_story | filter event_type = ENUM.NETWORK and ((action_local_port = 135 or action_remote_port = 135) and (action_local_ip = "1.1.1.1" or action_remote_ip = "1.1.1.1") and action_network_protocol = "udp" and (action_local_ip = "2.2.2.2" or action_remote_ip = "2.2.2.2") and (action_local_port = 80 or action_remote_port = 80) and (action_local_ip = "3.3.3.3" or action_remote_ip = "3.3.3.3") and (action_local_port = 8080 or action_remote_port = 8080))']

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