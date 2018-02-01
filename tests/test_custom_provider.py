import sys
import time
import uuid
import pytest
import datetime
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes

import boto3
from provider import handler

iam = boto3.client('iam')
elb = boto3.client('elbv2')
ec2 = boto3.client('ec2')

def generate_certificate(name):
    key = rsa.generate_private_key(public_exponent=65537, key_size=1024, backend=default_backend())
    subject = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, u"NL"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, u"Amsterdam"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"binx.io"),
        x509.NameAttribute(NameOID.COMMON_NAME, name)
    ])
    builder = x509.CertificateBuilder() \
        .subject_name(subject) \
        .issuer_name(subject) \
        .public_key(key.public_key()) \
        .serial_number(x509.random_serial_number()) \
        .not_valid_before(datetime.datetime.utcnow()) \
        .not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=10))

    cert = builder.sign(key, hashes.SHA256(), default_backend())

    return key, cert


loaded_certificates = []
def upload_certificate(name, key, cert):
    key = key.private_bytes(serialization.Encoding.PEM,
                            serialization.PrivateFormat.PKCS8,
                            serialization.NoEncryption()).decode()
    body = cert.public_bytes(serialization.Encoding.PEM).decode()
    response = iam.upload_server_certificate(ServerCertificateName=name, CertificateBody=body, PrivateKey=key)
    loaded_certificates.append(name)
    sys.stderr.write('INFO: waiting 10s for certificate {} to propagate.\n'.format(name))
    time.sleep(15)
    return response['ServerCertificateMetadata']['Arn']

def generate_and_upload_certificate(name):
    key, cert = generate_certificate(name)
    return upload_certificate(name, key, cert)


def delete_certificates():
    for name in loaded_certificates:
        for retry in range(0,4):
            try:
                iam.delete_server_certificate(ServerCertificateName=name)
                sys.stderr.write('INFO: deleted certificate {}\n'.format(name))
                break
            except iam.exceptions.NoSuchEntityException as e:
                sys.stderr.write('INFO: deleted no existing certificate {}\n'.format(name))
                break
            except iam.exceptions.DeleteConflictException as e:
                if retry < 3:
                    # AWS sometimes takes a while before it detects the certificate is no longer used
                    sys.stderr.write('INFO: delete certificate {} conflicted, retrying..\n'.format(name))
                    time.sleep((retry + 1)* 5)
                    continue
                else:
                    sys.stderr.write('ERROR: Failed to delete certificate {} after {} retries, {}\n'.format(name, retry, e.message))
            except Exception as e:
                sys.stderr.write('ERROR: Failed to delete certificate {}, {}\n'.format(name, e.message))


loadbalancers = []
def create_lb_listener(name):
    response = ec2.describe_vpcs(Filters=[{'Name': 'isDefault', 'Values': ['true']}])
    assert len(response['Vpcs']) == 1, 'no default VPC found.'
    vpc_id = response['Vpcs'][0]['VpcId']

    response = ec2.describe_subnets(Filters=[{'Name': 'vpc-id', 'Values': [vpc_id]}])
    assert len(response['Subnets']) > 0, 'no subnets for VPC {} found.'.format(vpc_id)
    subnets = response['Subnets']

    subnet1 = subnets[0]['SubnetId']
    az1 = subnets[0]['AvailabilityZone']
    subnets = list(filter(lambda s: s['AvailabilityZone'] != az1, subnets))
    assert len(response['Subnets']) >= 1, 'no subnet found in an AZ other than {}.'.format(az1)
    subnet2 = subnets[0]['SubnetId']

    cert_arn = generate_and_upload_certificate(name)
    certificates = [{'CertificateArn': cert_arn}]

    response = elb.create_load_balancer(Name=name[:32],
                                        Type='application', Scheme='internal', Subnets=[subnet1, subnet2])
    lb_arn = response['LoadBalancers'][0]['LoadBalancerArn']
    loadbalancers.append((lb_arn, None, None))

    response = elb.create_target_group(Name=name[:32], Protocol='HTTP', Port=80, VpcId=vpc_id)
    target_group_arn = response['TargetGroups'][0]['TargetGroupArn']
    loadbalancers[-1] = (lb_arn, target_group_arn, None)

    try:
        response = elb.create_listener(LoadBalancerArn=lb_arn, Protocol='HTTPS', Port=443, Certificates=certificates,
                                       DefaultActions=[{'Type': 'forward', 'TargetGroupArn': target_group_arn}])
        listener_arn = response['Listeners'][0]['ListenerArn']
        loadbalancers[-1] = (lb_arn, target_group_arn, listener_arn)
    except Exception as e:
        raise

    return loadbalancers[-1]

def delete_load_balancers():
    for lb_arn, target_group_arn, listener_arn in loadbalancers:
        if listener_arn is not None:
            try:
                sys.stderr.write('INFO: deleting listener {}\n'.format(listener_arn))
                elb.delete_listener(ListenerArn=listener_arn)
            except Exception as e:
                sys.stderr.write('ERROR: Failed to delete {}, {}\n'.format(listener_arn, e.message))

        try:
            sys.stderr.write('INFO: deleting lb {}\n'.format(lb_arn))
            elb.delete_load_balancer(LoadBalancerArn=lb_arn)
        except Exception as e:
            sys.stderr.write('ERROR: Failed to delete {}, {}\n'.format(lb_arn, e.message))

        if target_group_arn is not None:
            try:
                sys.stderr.write('INFO: deleting tg {}\n'.format(target_group_arn))
                elb.delete_target_group(TargetGroupArn=target_group_arn)
            except Exception as e:
                sys.stderr.write('ERROR: Failed to delete {}, {}\n'.format(target_group_arn, e.message))
        time.sleep(1)





@pytest.yield_fixture(scope="session", autouse=True)
def setup():
    yield
    delete_load_balancers()
    delete_certificates()

def test_create():
    name = 'test-%s' % uuid.uuid4()

    loadbalancer_arn, tg_arn, listener_arn = create_lb_listener(name)
    cert_arn = generate_and_upload_certificate('test-{}'.format(name))

    request = Request('Create', listener_arn, cert_arn)
    response = handler(request, {})
    assert response['Status'] == 'SUCCESS', response['Reason']
    assert 'PhysicalResourceId' in response
    parts = response['PhysicalResourceId'].split(' ', 2)
    assert len(parts) == 2
    assert parts[0] == listener_arn
    assert parts[1] == cert_arn

    physical_resource_id = response['PhysicalResourceId']
    request = Request('Update', listener_arn, cert_arn, physical_resource_id)
    response = handler(request, {})
    assert response['Status'] == 'SUCCESS', response['Reason']
    assert 'PhysicalResourceId' in response
    assert response['PhysicalResourceId'] == physical_resource_id


    # delete
    physical_resource_id = response['PhysicalResourceId']
    request = Request('Delete', listener_arn, cert_arn, physical_resource_id)
    assert response['Status'] == 'SUCCESS', response['Reason']


def xtest_update():
    # create
    value = 'v%s' % uuid.uuid4()
    request = Request('Create', value)
    response = handler(request, {})

    assert response['Status'] == 'SUCCESS', response['Reason']
    assert 'PhysicalResourceId' in response
    assert 'Value' in response['Data']
    assert response['Data']['Value'] == value

    # update to a new value
    new_value = 'new-%s' % value
    physical_resource_id = response['PhysicalResourceId']
    request = Request('Update', new_value, physical_resource_id)
    response = handler(request, {})

    assert response['Status'] == 'SUCCESS', response['Reason']
    assert 'PhysicalResourceId' in response
    assert 'Value' in response['Data']
    assert response['Data']['Value'] == new_value

    # delete the last created
    physical_resource_id = response['PhysicalResourceId']
    request = Request('Delete', new_value, physical_resource_id)
    assert response['Status'] == 'SUCCESS', response['Reason']


class Request(dict):

    def __init__(self, request_type, listener_arn, certificate_arn, physical_resource_id=None):
        request_id = 'request-%s' % uuid.uuid4()
        self.update({
            'RequestType': request_type,
            'ResponseURL': 'https://httpbin.org/put',
            'StackId': 'arn:aws:cloudformation:us-west-2:EXAMPLE/stack-name/guid',
            'RequestId': request_id,
            'ResourceType': 'Custom::ListenerCertificate',
            'LogicalResourceId': 'ListenerCertificate',
            'ResourceProperties': {
                'ListenerArn': listener_arn,
                'CertificateArn': certificate_arn
            }})

        self['PhysicalResourceId'] = physical_resource_id if physical_resource_id is not None else 'initial-%s' % str(
            uuid.uuid4())
