import boto3
from botocore.exceptions import ClientError

def delete_all_objects_in_bucket(s3, bucket_name):
    try:
        paginator = s3.get_paginator('list_objects_v2')
        pages = paginator.paginate(Bucket=bucket_name)

        for page in pages:
            if 'Contents' in page:
                for obj in page['Contents']:
                    s3.delete_object(Bucket=bucket_name, Key=obj['Key'])
                    print(f'Deleted {obj["Key"]} from {bucket_name}')
    except ClientError as e:
        print(f'Error deleting objects: {e}')

def delete_bucket(s3, bucket_name):
    try:
        s3.delete_bucket(Bucket=bucket_name)
        print(f'Bucket {bucket_name} deleted successfully')
    except ClientError as e:
        print(f'Error deleting bucket: {e}')

def get_default_vpc_id(ec2_client):
    try:
        response = ec2_client.describe_vpcs(Filters=[{'Name': 'tag:Name', 'Values': ["default_vpc"]}])
        if response['Vpcs']:
            vpc_id = response['Vpcs'][0]['VpcId']
            print(f"VPC default_vpc already exists. VPC id : {vpc_id}")

            response = ec2_client.describe_security_groups(
                Filters=[
                    {'Name': 'vpc-id', 'Values': [vpc_id]},
                    {'Name': 'group-name', 'Values': ['testec2-sg']}
                ]
            )
            if response['SecurityGroups']:
                for sg in response['SecurityGroups']:
                    sg_id = sg['GroupId']
                    print(f"Security group testec2-sg already exists. SG id : {sg_id}")
                    current_ports = set()
                    
                    for rule in sg['IpPermissions']:
                        from_port = rule.get('FromPort')
                        to_port = rule.get('ToPort')
                        
                        if from_port == to_port:
                            current_ports.add(from_port)
                return vpc_id, sg_id, current_ports
            else:
                return vpc_id, None, set() 
        else:
            return None, None, set()
    except ClientError as e:
        print(f"An error occurred: {e}")
        return None, None, set()

def check_ec2_instance(ec2_client, servername):
    try:
        response = ec2_client.describe_instances(
            Filters=[
                {'Name': 'tag:Name', 'Values': [servername]},
                {'Name': 'instance-state-name', 'Values': ['running']}
            ]
        )

        if 'Reservations' in response:
            for reservation in response['Reservations']:
                for instance in reservation['Instances']:
                    print(f"{servername} Instance Already Present, Instance ID: {instance['InstanceId']}")
                    return instance['InstanceId']
        else:
            return None
    except ClientError as e:
        print(f"An error occurred: {e}")

def check_mern_ami(ec2_client, ami_name):
    try:
        existing_amis = ec2_client.describe_images(Filters=[{'Name': 'name', 'Values': [ami_name]}])
        if existing_amis['Images']:
            print(f"AMI with name '{ami_name}' already exists. AMI id : {existing_amis['Images'][0]['ImageId']}")
            return existing_amis['Images'][0]['ImageId']
        else:
            return None
    except ClientError as e:
        print(f"An error occurred: {e}")
        return None

def check_key_pair(ec2_client, key_pair_name):
    try:
        existing_key_pairs = ec2_client.describe_key_pairs()
        for existing_key_pair in existing_key_pairs['KeyPairs']:
            if existing_key_pair['KeyName'] == key_pair_name:
                return True
        return False
    except ClientError as e:
        print(f"An error occurred: {e}")
        return False

def check_existing_target_group(elbv2_client, target_group_name):
    try:
        response = elbv2_client.describe_target_groups()
        if response['TargetGroups']:
            for target_group in response['TargetGroups']:
                if target_group['TargetGroupName'] == target_group_name:
                    target_group_arn = target_group['TargetGroupArn']
                    return target_group_arn
        else:
            return False
    except ClientError as e:
        print(f"An error occurred: {e}")
        return False

def get_subnet_ids_for_vpc(ec2_client, vpc_id):
    subnet_ids = []
    response = ec2_client.describe_subnets(
        Filters=[
            {
                'Name': 'vpc-id',
                'Values': [vpc_id]
            }
        ]
    )
    for subnet in response["Subnets"]:
        subnet_ids.append(subnet['SubnetId'])
    return subnet_ids

def check_load_balancer_exists(elbv2_client, lb_name):
    try:
        response = elbv2_client.describe_load_balancers(
            Names=[lb_name]
        )
        if response['LoadBalancers']:
            return response['LoadBalancers'][0]['LoadBalancerArn']
        else:
            return None
    except ClientError as e:
        if e.response['Error']['Code'] == 'LoadBalancerNotFound':
            print(f"Load balancer '{lb_name}' not found.")
        else:
            print(f"An error occurred: {e}")
        return None

def check_listener_exists(elbv2_client, load_balancer_arn):
    try:
        if load_balancer_arn:
            response = elbv2_client.describe_listeners(LoadBalancerArn=load_balancer_arn)
            if response['Listeners']:
                return response['Listeners'][0]['ListenerArn']
        else:
            print("Load balancer arn is None, cannot describe listeners.")
        return None
    except ClientError as e:
        print(f"An error occurred: {e}")
        return None

def check_launch_configuration(autoscaling, launch_configuration_name):
    try:
        response = autoscaling.describe_launch_configurations(
            LaunchConfigurationNames=[launch_configuration_name]
        )
        if response['LaunchConfigurations']:
            for launch_config in response['LaunchConfigurations']:
                if launch_config['LaunchConfigurationName'] == launch_configuration_name:
                    print(f"Launch configuration '{launch_configuration_name}' already exists.")
                    return True
        return False
    except ClientError as e:
        print(f"An error occurred: {e}")
        return False

def check_autoscaling(autoscaling, autoscalingName):
    try:
        response = autoscaling.describe_auto_scaling_groups(
            AutoScalingGroupNames=[autoscalingName]
        )
        if response['AutoScalingGroups']:
            for asg in response['AutoScalingGroups']:
                if asg['AutoScalingGroupName'] == autoscalingName:
                    print(f"Auto scaling group '{autoscalingName}' already exists.")
                    return True
        print(f"Auto scaling group '{autoscalingName}' not found.")
        return False
    except ClientError as e:
        print(f"An error occurred: {e}")
        return False

def check_scaling_policy_existence(autoscaling, asg_name, policy_name):
    try:
        response = autoscaling.describe_policies(
            AutoScalingGroupName=asg_name,
            PolicyNames=[policy_name]
        )
        if response['ScalingPolicies']:
            for policy in response['ScalingPolicies']:
                if policy['PolicyName'] == policy_name:
                    return True
        return False
    except ClientError as e:
        print(f"An error occurred: {e}")
        return False

def delete_ec2_instance(ec2_client, instance_id):
    try:
        ec2_client.terminate_instances(InstanceIds=[instance_id])
        print(f"Terminated EC2 instance with ID: {instance_id}")
    except ClientError as e:
        print(f"Failed to terminate instance {instance_id}: {e}")

def deregister_ami(ec2_client, ami_id):
    try:
        ec2_client.deregister_image(ImageId=ami_id)
        print(f"Deregistered AMI with ID: {ami_id}")
    except ClientError as e:
        print(f"Failed to deregister AMI {ami_id}: {e}")

def delete_security_group(ec2_client, sg_id):
    try:
        ec2_client.delete_security_group(GroupId=sg_id)
        print(f"Deleted security group with ID: {sg_id}")
    except ClientError as e:
        print(f"Failed to delete security group {sg_id}: {e}")

def delete_load_balancer(elbv2_client, load_balancer_arn):
    try:
        elbv2_client.delete_load_balancer(LoadBalancerArn=load_balancer_arn)
        print(f"Deleted load balancer with ARN: {load_balancer_arn}")
    except ClientError as e:
        print(f"Failed to delete load balancer {load_balancer_arn}: {e}")

def delete_listener(elbv2_client, listener_arn):
    try:
        elbv2_client.delete_listener(ListenerArn=listener_arn)
        print(f"Deleted listener with ARN: {listener_arn}")
    except ClientError as e:
        print(f"Failed to delete listener {listener_arn}: {e}")

def delete_launch_configuration(autoscaling, launch_configuration_name):
    try:
        autoscaling.delete_launch_configuration(LaunchConfigurationName=launch_configuration_name)
        print(f"Deleted launch configuration: {launch_configuration_name}")
    except ClientError as e:
        print(f"Failed to delete launch configuration {launch_configuration_name}: {e}")

def delete_auto_scaling_group(autoscaling, autoscalingName):
    try:
        autoscaling.delete_auto_scaling_group(AutoScalingGroupName=autoscalingName, ForceDelete=True)
        print(f"Deleted auto scaling group: {autoscalingName}")
    except ClientError as e:
        print(f"Failed to delete auto scaling group {autoscalingName}: {e}")

def delete_scaling_policy(autoscaling, asg_name, policy_name):
    try:
        autoscaling.delete_policy(AutoScalingGroupName=asg_name, PolicyName=policy_name)
        print(f"Deleted scaling policy: {policy_name} for Auto Scaling Group: {asg_name}")
    except ClientError as e:
        print(f"Failed to delete scaling policy {policy_name} for Auto Scaling Group {asg_name}: {e}")

def delete_vpc(ec2_client, vpc_id):
    try:
        ec2_client.delete_vpc(VpcId=vpc_id)
        print(f"Deleted VPC with ID: {vpc_id}")
    except ClientError as e:
        print(f"Failed to delete VPC {vpc_id}: {e}")

def delete_key_pair(ec2_client, key_pair):
    try:
        ec2_client.delete_key_pair(KeyName=key_pair)
        print(f"Deleted key pair: {key_pair}")
    except ClientError as e:
        print(f"Failed to delete key pair {key_pair}: {e}")

def delete_target_group(elbv2_client, target_group):
    try:
        elbv2_client.delete_target_group(TargetGroupArn=target_group)
        print(f"Deleted target group: {target_group}")
    except ClientError as  e:
        print(f"Failed to delete target group {target_group}: {e}")

def main():
    key_pair_name = 'monitoring_ec2'
    ami_name = 'AMIImageofwebserver'
    target_group_name = "MyTargetGroup"
    lb_name = 'monitoring-load-balancing'
    autoscalingName = "monitoringautoscale"
    policyName = "monitroingploicy"
    launch_configuration_name = "monitoring_launch_configuration"
    bucket_name = 'sukhilmybucket2'

    session = boto3.Session(profile_name='profile1', region_name="ap-northeast-2")
    ec2_client = session.client('ec2')
    elbv2_client = session.client('elbv2')
    autoscaling = session.client('autoscaling')
    s3 = session.client('s3')

    vpc_id, sg_id, current_ports = get_default_vpc_id(ec2_client)

    primary_instance_id = check_ec2_instance(ec2_client, servername='primaryserver')
    secondary_instance_id = check_ec2_instance(ec2_client, servername='secondaryserver')

    ami_id = check_mern_ami(ec2_client, ami_name)
    key_pair = check_key_pair(ec2_client, key_pair_name)
    target_group = check_existing_target_group(elbv2_client, target_group_name)

    subnets = get_subnet_ids_for_vpc(ec2_client, vpc_id)
    load_balancing_arn = check_load_balancer_exists(elbv2_client, lb_name)
    listener_arn = check_listener_exists(elbv2_client, load_balancing_arn)
    launch_config_exists = check_launch_configuration(autoscaling, launch_configuration_name)
    autoscaling_exists = check_autoscaling(autoscaling, autoscalingName)
    scaling_policy_exists = check_scaling_policy_existence(autoscaling, autoscalingName, policyName)

    delete_all_objects_in_bucket(s3,bucket_name)

    delete_bucket(s3, bucket_name)
    
    if primary_instance_id:
        delete_ec2_instance(ec2_client, primary_instance_id)
    
    if secondary_instance_id:
        delete_ec2_instance(ec2_client, secondary_instance_id)
    
    if ami_id:
        deregister_ami(ec2_client, ami_id)

    if vpc_id:
        delete_vpc(ec2_client, vpc_id)
    
    if sg_id:
        delete_security_group(ec2_client, sg_id)
    
    if load_balancing_arn:
        delete_load_balancer(elbv2_client, load_balancing_arn)
    
    if listener_arn:
        delete_listener(elbv2_client, listener_arn)
    
    if autoscaling_exists:
        delete_auto_scaling_group(autoscaling, autoscalingName)
    
    if scaling_policy_exists:
        delete_scaling_policy(autoscaling, autoscalingName, policyName)
    
    if launch_config_exists:
        delete_launch_configuration(autoscaling, launch_configuration_name)

    if key_pair:
        delete_key_pair(ec2_client, key_pair_name)
    
    if target_group:
        delete_target_group(elbv2_client, target_group)

if __name__ == "__main__":
    main()
