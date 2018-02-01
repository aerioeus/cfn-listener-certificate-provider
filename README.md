# cfn-listener-certificate-provider
A CloudFormation custom resource provider for managing additional certificates .

This is because the [AWS::ElasticLoadBalancingV2::Listener](https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-elasticloadbalancingv2-listener.html) resources does not implement support for multiple certificates (2018-01-31).

## How do I add a certificate:
It is quite easy: you specify a CloudFormation resource of the type Custom::ListenerCertificate, as fllows

```yaml
    AdditionalCertificate:
      Type: Custom::ListenerCertificate
      Properties: 
        ListenerArn: !Ref Listener
        CertificateArn: !Ref Certificate
        ServiceToken: !Sub 'arn:aws:lambda:${AWS::Region}:${AWS::AccountId}:function:binxio-cfn-listener-certificate-provider'
```
After the deployment, the certificate is added to the listener.

## Installation
To install these custom resources, type:

```sh
aws cloudformation create-stack \
	--capabilities CAPABILITY_IAM \
	--stack-name cfn-listener-certificate-provider \
	--template-body file://cloudformation/cfn-listener-certificate-provider.yaml

aws cloudformation wait stack-create-complete  --stack-name cfn-listener-certificate-provider 
```

This CloudFormation template will use our pre-packaged provider from `s3://binxio-public/lambdas/cfn-listener-certificate-provider-latest.zip`.


