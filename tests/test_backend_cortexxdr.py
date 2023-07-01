import pytest
from sigma.collection import SigmaCollection
from sigma.backends.cortexxdr import CortexXDRBackend

@pytest.fixture
def cortexxdr_backend():
    return CortexXDRBackend()

def test_cortexxdr_and_expression(cortexxdr_backend : CortexXDRBackend):
    assert cortexxdr_backend.convert(
        SigmaCollection.from_yaml("""
            title: Test
            status: test
            logsource:
                category: process_creation
                product: test_product
            detection:
                sel:
                    Image: valueA
                    ParentImage: valueB
                condition: sel
        """)
    ) == ['dataset=xdr_data | filter (event_type = ENUM.PROCESS and event_sub_type = ENUM.PROCESS_START) and (action_process_image_path = "valueA" and actor_process_image_path = "valueB")']

def test_cortexxdr_or_expression(cortexxdr_backend : CortexXDRBackend):
    assert cortexxdr_backend.convert(
        SigmaCollection.from_yaml("""
            title: Test
            status: test
            logsource:
                category: process_creation
                product: test_product
            detection:
                sel1:
                    Image: valueA
                sel2:
                    ParentImage: valueB
                condition: 1 of sel*
        """)
    ) == ['dataset=xdr_data | filter (event_type = ENUM.PROCESS and event_sub_type = ENUM.PROCESS_START) and (action_process_image_path = "valueA" or actor_process_image_path = "valueB")']

def test_cortexxdr_and_or_expression(cortexxdr_backend : CortexXDRBackend):
    assert cortexxdr_backend.convert(
        SigmaCollection.from_yaml("""
            title: Test
            status: test
            logsource:
                category: process_creation
                product: test_product
            detection:
                sel:
                    Image:
                        - valueA1
                        - valueA2
                    ParentImage:
                        - valueB1
                        - valueB2
                condition: sel
        """)
    ) == ['dataset=xdr_data | filter (event_type = ENUM.PROCESS and event_sub_type = ENUM.PROCESS_START) and ((action_process_image_path in ("valueA1", "valueA2")) and (actor_process_image_path in ("valueB1", "valueB2")))']

def test_cortexxdr_or_and_expression(cortexxdr_backend : CortexXDRBackend):
    assert cortexxdr_backend.convert(
        SigmaCollection.from_yaml("""
            title: Test
            status: test
            logsource:
                category: process_creation
                product: test_product
            detection:
                sel1:
                    Image: valueA1
                    ParentImage: valueB1
                sel2:
                    Image: valueA2
                    ParentImage: valueB2
                condition: 1 of sel*
        """)
    ) == ['dataset=xdr_data | filter (event_type = ENUM.PROCESS and event_sub_type = ENUM.PROCESS_START) and ((action_process_image_path = "valueA1" and actor_process_image_path = "valueB1") or (action_process_image_path = "valueA2" and actor_process_image_path = "valueB2"))']

def test_cortexxdr_in_expression(cortexxdr_backend : CortexXDRBackend):
    assert cortexxdr_backend.convert(
        SigmaCollection.from_yaml("""
            title: Test
            status: test
            logsource:
                category: process_creation
                product: test_product
            detection:
                sel:
                    Image:
                        - valueA
                        - valueB
                        - valueC*
                condition: sel
        """)
    ) == ['dataset=xdr_data | filter (event_type = ENUM.PROCESS and event_sub_type = ENUM.PROCESS_START) and (action_process_image_path in ("valueA", "valueB", "valueC*"))']

def test_cortexxdr_regex_query(cortexxdr_backend : CortexXDRBackend):
    assert cortexxdr_backend.convert(
        SigmaCollection.from_yaml("""
            title: Test
            status: test
            logsource:
                category: process_creation
                product: test_product
            detection:
                sel:
                    Image|re: foo.*bar
                    ParentImage: foo
                condition: sel
        """)
    ) == ['dataset=xdr_data | filter (event_type = ENUM.PROCESS and event_sub_type = ENUM.PROCESS_START) and (action_process_image_path ~= "foo.*bar" and actor_process_image_path = "foo")']

def test_cortexxdr_cidr_query(cortexxdr_backend : CortexXDRBackend):
    assert cortexxdr_backend.convert(
        SigmaCollection.from_yaml("""
            title: Test
            status: test
            logsource:
                category: network_connection
                product: test_product
            detection:
                sel:
                    SourceIp|cidr: 192.168.0.0/16
                condition: sel
        """)
    ) == ['dataset=xdr_data | filter event_type = ENUM.NETWORK and (action_local_ip incidr "192.168.0.0/16" or action_remote_ip incidr "192.168.0.0/16")']


def test_cortexxdr_default_output(cortexxdr_backend : CortexXDRBackend):
    """Test for output format default."""
    assert cortexxdr_backend.convert(
        SigmaCollection.from_yaml("""
            title: Test
            status: test
            logsource:
                category: process_creation
                product: test_product
            detection:
                sel:
                    Image: valueA
                condition: sel
        """)
    ) == ['dataset=xdr_data | filter (event_type = ENUM.PROCESS and event_sub_type = ENUM.PROCESS_START) and action_process_image_path = "valueA"']

def test_cortexxdr_json_output(cortexxdr_backend : CortexXDRBackend):
    """Test for output format json."""
    # TODO: implement a test for the output format
    assert cortexxdr_backend.convert(
        SigmaCollection.from_yaml("""
            title: Test
            status: test
            logsource:
                category: process_creation
                product: test_product
            detection:
                sel:
                    Image: valueA
                condition: sel
        """)
    ) == {"queries":[{"query":'dataset=xdr_data | filter (event_type = ENUM.PROCESS and event_sub_type = ENUM.PROCESS_START) and action_process_image_path = "valueA"', "title":"Test", "id":None, "description":None}]}


