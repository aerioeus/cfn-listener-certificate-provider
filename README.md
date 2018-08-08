# cfn-listener-certificate-provider
A CloudFormation custom resource provider for managing additional certificates, was created as the [AWS::ElasticLoadBalancingV2::Listener](https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-elasticloadbalancingv2-listener.html) does not implement support for multiple certificates (2018-01-31).

It is no longer relevant (2018-08-08). Use the [AWS::ElasticLoadBalancingV2::ListenerCertificate](https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-elasticloadbalancingv2-listenercertificate.html) instead. 

## How do I add a certificate:
It is quite easy: you specify a CloudFormation resource of the type Custom::ListenerCertificate, as fllows

```yaml
    AdditionalCertificate:
      Type: AWS::ElasticLoadBalancingV2::ListenerCertificate
      Properties: 
        ListenerArn: !Ref Listener
        CertificateArn: 
          - !Ref Certificate
```
After the deployment, the certificate is added to the listener.
