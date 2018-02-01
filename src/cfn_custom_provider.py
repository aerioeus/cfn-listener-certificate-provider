from cfn_resource_provider import ResourceProvider
import boto3
from botocore.exceptions import ClientError

#
# The request schema defining the Resource Properties
#
request_schema = {
    "type": "object",
    "required": ["ListenerArn", "CertificateArn"],
    "properties": {
        "ListenerArn": {
            "type": "string",
            "description": "The ARN of the listener to add the certificate to"
        },
        "CertificateArn": {
            "type": "string",
            "description": "The ARN of the certificate to add the listener"
        }
    }
}


class ListenerCertificateProvider(ResourceProvider):

    def __init__(self):
        super(ResourceProvider, self).__init__()
        self.request_schema = request_schema
        self.elbv2 = boto3.client('elbv2')

    def convert_property_types(self):
        self.heuristic_convert_property_types(self.properties)

    @property
    def certificate_arn(self):
        return self.get('CertificateArn')

    @property
    def listener_arn(self):
        return self.get('ListenerArn')

    def create_or_update(self):
        try:
            certificates = [{'CertificateArn': self.certificate_arn}]
            response = self.elbv2.add_listener_certificates(Certificates=certificates, ListenerArn=self.listener_arn)
            self.physical_resource_id = "{} {}".format(self.listener_arn, self.certificate_arn)
        except ClientError as e:
            self.fail(e['Error']['Message'])
            if self.request_type == 'Create':
                self.physical_resource_id = 'failed-to-create'

    def create(self):
        self.create_or_update()

    def update(self):
        self.create_or_update()

    def delete(self):
        if self.physical_resource_id == 'failed-to-create':
            return

        try:
            (listener_arn, certificate_arn) = self.physical_resource_id.split(' ', 2)
            certificates=[{'CertificateArn': certificate_arn}]
            response = self.elbv2.remove_listener_certificates(ListenerArn=listener_arn, Certificates=certificates)
        except self.elbv2.exceptions.ListenerNotFoundException as e:
            self.success('listener already deleted')
        except self.elbv2.exceptions.CertificateNotFoundException as e:
            self.success('certificate already deleted')
        except ClientError as e:
            self.fail(e['Error']['Message'])


provider = ListenerCertificateProvider()


def handler(request, context):
    return provider.handle(request, context)
