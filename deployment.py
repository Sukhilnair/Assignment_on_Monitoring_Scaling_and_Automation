import boto3
from botocore.exceptions import ClientError
import time
import ipaddress


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
                    print(f"Security group testec2-sg already exists. VPC id : {sg_id}")
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

def update_default_security_group(ec2_client, required_ports, current_ports, sg_id):
    try:
        ports_to_add = required_ports - current_ports
        ports_to_remove = current_ports - required_ports
        
        if ports_to_add:
            print(f"Adding ports {ports_to_add} to security group {sg_id}")
            for port in ports_to_add:
                ec2_client.authorize_security_group_ingress(
                    GroupId=sg_id,
                    IpPermissions=[{
                        'IpProtocol': 'tcp',
                        'FromPort': port,
                        'ToPort': port,
                        'IpRanges': [{'CidrIp': '0.0.0.0/0'}]
                    }]
                )
        
        if ports_to_remove:
            print(f"Removing ports {ports_to_remove} from security group {sg_id}")
            for port in ports_to_remove:
                if port is not None:  # Check if port is not None
                    ec2_client.revoke_security_group_ingress(
                        GroupId=sg_id,
                        IpPermissions=[{
                            'IpProtocol': 'tcp',
                            'FromPort': port,
                            'ToPort': port,
                            'IpRanges': [{'CidrIp': '0.0.0.0/0'}]
                        }]
                    )
    except ClientError as e:
        print(f"An error occurred: {e}")

def fetch_ami_id(ec2_client):
    try:
        response = ec2_client.describe_images(Owners=['099720109477'])

        for image in response['Images']:
            if image['Name'] == "ubuntu/images/hvm-ssd/ubuntu-jammy-22.04-amd64-server-20240411":
                image_id = image['ImageId']
                print(f"Image name: {image['Name']} and Image ID is: {image_id}")
                return image_id
    except ClientError as e:
        print(f"An error occurred: {e}")
    return None
def get_subnet_id(ec2_client, vpc_id):
    try:
        response = ec2_client.describe_subnets(Filters=[{'Name': 'vpc-id', 'Values': [vpc_id]}])
        if response['Subnets']:
            return response['Subnets'][0]['SubnetId'] 
        else:
            print("No subnets found in the specified VPC.")
            return None
    except ClientError as e:
        print(f"An error occurred: {e}")
        return None
def create_key_pair(ec2_client, key_pair_name):
    try:
        # Check if key pair already exists
        existing_key_pairs = ec2_client.describe_key_pairs()
        for existing_key_pair in existing_key_pairs['KeyPairs']:
            if existing_key_pair['KeyName'] == key_pair_name:
                print(f"Key pair {key_pair_name} already exists.")
                return
        # Create key pair if it doesn't exist
        key_pair_response = ec2_client.create_key_pair(KeyName=key_pair_name)
        with open(f'{key_pair_name}.pem', 'w') as key_file:
            key_file.write(key_pair_response['KeyMaterial'])
        print(f"Key pair {key_pair_name} created and saved.")
    except ClientError as e:
        print(f"An error occurred: {e}")

def create_security_group(ec2_client, vpc_id):
    try:
        # Create security group if it doesn't exist
        response = ec2_client.create_security_group(
            GroupName='testec2-sg',
            Description='Security group for test EC2 instance',
            VpcId=vpc_id
        )
        security_group_id = response['GroupId']
        print(f"Security Group Created {security_group_id} in VPC {vpc_id}")

        return security_group_id
    except ClientError as e:
        print(f"An error occurred: {e}")
        return None

def create_vpc(ec2_client):
    try:
        response = ec2_client.create_vpc(
            CidrBlock='10.0.0.0/16'
        )
        vpc_id = response['Vpc']['VpcId']
        ec2_client.create_tags(
            Resources=[vpc_id],
            Tags=[{'Key': 'Name', 'Value': 'default_vpc'}]
        )
        ec2_client.modify_vpc_attribute(
            VpcId=vpc_id,
            EnableDnsSupport={'Value': True}
        )
        ec2_client.modify_vpc_attribute(
            VpcId=vpc_id,
            EnableDnsHostnames={'Value': True}
        )

        # Create a subnet
        subnet_response = ec2_client.create_subnet(
            VpcId=vpc_id,
            CidrBlock='10.0.1.0/24'
        )
        subnet_id = subnet_response['Subnet']['SubnetId']
        ec2_client.create_tags(
            Resources=[subnet_id],
            Tags=[{'Key': 'Name', 'Value': 'default_subnet'}]
        )

        # Create an Internet Gateway
        igw_response = ec2_client.create_internet_gateway()
        igw_id = igw_response['InternetGateway']['InternetGatewayId']
        ec2_client.attach_internet_gateway(
            InternetGatewayId=igw_id,
            VpcId=vpc_id
        )

        # Create a route table and a public route
        route_table_response = ec2_client.create_route_table(
            VpcId=vpc_id
        )
        route_table_id = route_table_response['RouteTable']['RouteTableId']
        ec2_client.create_route(
            RouteTableId=route_table_id,
            DestinationCidrBlock='0.0.0.0/0',
            GatewayId=igw_id
        )

        # Associate the subnet with the route table
        ec2_client.associate_route_table(
            RouteTableId=route_table_id,
            SubnetId=subnet_id
        )

        # Enable auto-assign public IP on the subnet
        ec2_client.modify_subnet_attribute(
            SubnetId=subnet_id,
            MapPublicIpOnLaunch={'Value': True}
        )

        return vpc_id
    except ClientError as e:
        print(f"An error occurred: {e}")

def get_subnet_ids_for_vpc(ec2_client,vpc_id):
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
            print(f"AMI with name '{ami_name}' already exists. Skipping AMI creation. AMI id : {existing_amis['Images'][0]['ImageId']}")
            return existing_amis['Images'][0]['ImageId']
        else:
            return None
    except ClientError as e:
        print(f"An error occurred: {e}")
        return None
def create_ami(ec2_client, instance_id, ami_name):
    try:
        response = ec2_client.create_image(
            InstanceId=instance_id,
            Name=ami_name,
            Description='AMI created from running MERN instance',
            NoReboot=True
        )
        ami_id = response['ImageId']
        print(f"AMI {ami_id} created from instance {instance_id}")
        return ami_id
    except ClientError as e:
        print(f"An error occurred: {e}")
        return None
def create_ec2_instance(ec2_client,key_pair_name,sg_id,ami_image_id,user_data_script,subnet_id,servername):
    try:
        instance_response = ec2_client.run_instances(
            ImageId=ami_image_id,
            InstanceType='t3.micro',
            KeyName=key_pair_name,
            MinCount=1,
            MaxCount=1,
            TagSpecifications=[
                {
                    'ResourceType': 'instance',
                    'Tags': [
                        {
                            'Key': 'Name',
                            'Value': servername
                        }
                    ]
                }
            ],
            SubnetId=subnet_id,
            SecurityGroupIds=[sg_id],
            UserData=user_data_script
        )
        if 'Instances' in instance_response:
            for instance in instance_response['Instances']:
                for tag in instance['Tags']:
                    if tag['Key'] == 'Name' and tag['Value'] == servername:
                        instance_id = instance['InstanceId']
                        break
            return instance_id
        else:
            return None
    except ClientError as e:
        print(f"An error occurred: {e}")

def check_existing_target_group(elbv2_client, target_group_name):
    try:
        response = elbv2_client.describe_target_groups()
        if response['TargetGroups']:
            for target_group in response['TargetGroups']:
                if target_group['TargetGroupName'] == target_group_name:
                    target_group_arn = target_group['TargetGroupArn']
                    return target_group_arn
        else:
            return None
    except ClientError as e:
        print(f"An error occurred: {e}")
        return None

def create_target_group_with_instances(elbv2_client, target_group_name, vpc_id, protocol, port, instances):
    try:
        existing_target_group_arn = check_existing_target_group(elbv2_client, target_group_name)
        if existing_target_group_arn:
            print(f"Target group {target_group_name} already exists with ARN: {existing_target_group_arn}")
            return existing_target_group_arn
        else:
            print("Target group with desired name is not present, Creating.....")
        
        # Create new target group if it doesn't exist
        response = elbv2_client.create_target_group(
            Name=target_group_name,
            Protocol=protocol,
            Port=port,
            VpcId=vpc_id,
            TargetType='instance',
            HealthCheckProtocol=protocol,
            HealthCheckPort=str(port),
            HealthCheckPath='/',
            HealthCheckIntervalSeconds=30,
            HealthCheckTimeoutSeconds=10,
            HealthyThresholdCount=3,
            UnhealthyThresholdCount=3
        )
        target_group_arn = response['TargetGroups'][0]['TargetGroupArn']
        print(f"Target group {target_group_name} created with ARN: {target_group_arn}")
        
        # Register instances with the target group
        if instances:
            for instance in instances:
                elbv2_client.register_targets(
                    TargetGroupArn=target_group_arn,
                    Targets=[
                        {
                            'Id': instance
                        }
                    ]
                )
                print(f"Instance {instance} registered with target group {target_group_name}")
        
        return target_group_arn
    except ClientError as e:
        print(f"An error occurred: {e}")
        return None

def get_available_cidr_blocks(vpc_cidr, used_cidrs, num_subnets):
    """
    Generate a list of available CIDR blocks for subnets within the given VPC CIDR block.
    """
    vpc_network = ipaddress.IPv4Network(vpc_cidr)
    available_subnets = list(vpc_network.subnets(new_prefix=24))

    # Filter out the used CIDR blocks
    available_subnets = [subnet for subnet in available_subnets if str(subnet) not in used_cidrs]

    # Return only the required number of subnets
    return available_subnets[:num_subnets]
def create_subnet(ec2_client, vpc_id, cidr_block):
    try: 
        response = ec2_client.describe_vpcs(VpcIds=[vpc_id])
        vpc_cidr_block = response['Vpcs'][0]['CidrBlock']

        # Get the list of availability zones in the specified region
        response = ec2_client.describe_availability_zones()
        availability_zones = [az['ZoneName'] for az in response['AvailabilityZones']]

        # Get existing subnets to avoid CIDR conflicts
        response = ec2_client.describe_subnets(Filters=[{'Name': 'vpc-id', 'Values': [vpc_id]}])
        existing_subnets = response['Subnets']
        used_cidrs = [subnet['CidrBlock'] for subnet in existing_subnets]

        # Generate available CIDR blocks
        available_cidrs = get_available_cidr_blocks(vpc_cidr_block, used_cidrs, len(availability_zones))

        if len(available_cidrs) < len(availability_zones):
            print("Not enough available CIDR blocks to create subnets in all availability zones.")
        else:
            # Create subnets in each availability zone
            subnet_ids = []

            for i, az in enumerate(availability_zones):
                cidr_block = str(available_cidrs[i])
                response = ec2_client.create_subnet(
                    VpcId=vpc_id,
                    CidrBlock=cidr_block,
                    AvailabilityZone=az
                )
                subnet_id = response['Subnet']['SubnetId']
                subnet_ids.append(subnet_id)
                print(f"Created subnet with ID: {subnet_id} in {az}")

            print("All subnets created:", subnet_ids)
        return subnet_ids
    except:
        return None

def check_load_balancer_exists(elb_client, lb_name):
    try:
        response = elb_client.describe_load_balancers(
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
def create_load_balancer(elb_client, lb_name, subnet_id, sg_id):
    try:
        response = elb_client.create_load_balancer(
            Name=lb_name,
            Subnets=subnet_id, 
            SecurityGroups=[sg_id],
            Scheme='internet-facing',
            Type='application',
            IpAddressType='ipv4'
        )
        if response['LoadBalancers']:
            return response['LoadBalancers'][0]['LoadBalancerArn']
        else:
            return None
    except ClientError as e:
        print(f"An error occurred while creating load balancer: {e}")
        return None


def check_listener_exists(elb_client, load_balancer_arn):
    try:
        response = elb_client.describe_listeners(LoadBalancerArn=load_balancer_arn)
        if response['Listeners']:
            return response['Listeners'][0]['ListenerArn']
        else:
            return None
    except ClientError as e:
        print(f"An error occurred: {e}")
        return None
def create_listener(elb_client, load_balancer_arn, target_group_arn):
    try:
        response = elb_client.create_listener(
            LoadBalancerArn=load_balancer_arn,
            Protocol='HTTP',
            Port=80,
            DefaultActions=[
                {
                    'Type': 'forward',
                    'TargetGroupArn': target_group_arn
                }
            ]
        )
        if response['Listeners']:
            return response['Listeners'][0]['ListenerArn']
        else:
            return None
    except ClientError as e:
        print(f"An error occurred: {e}")
        return None

def check_launch_configuration(autoscaling, launch_configuration_name):
    response = autoscaling.describe_launch_configurations(
        LaunchConfigurationNames=[launch_configuration_name]
    )
    # print (response)
    if response['LaunchConfigurations']:
        for LaunchConfiguration in response['LaunchConfigurations']:
            if LaunchConfiguration and LaunchConfiguration["LaunchConfigurationName"] == launch_configuration_name:
                print(f"Launch configuration '{launch_configuration_name}' already exists.")
                return True
    return False
def create_launch_configuration(autoscaling, launch_configuration_name, ami_id, key_pair_name, sg_id, user_data_script):
    try:
        response = autoscaling.create_launch_configuration(
            LaunchConfigurationName=launch_configuration_name,
            ImageId=ami_id,
            InstanceType='t2.micro',
            KeyName=key_pair_name,
            SecurityGroups=[sg_id], 
            UserData=user_data_script
        )
        print('Created launch configuration')
        return response
    except ClientError as e:
        print(f"An error occurred: {e}")
        return None

def check_autoscaling(autoscaling, autoscalingName):
    response = autoscaling.describe_auto_scaling_groups(
        AutoScalingGroupNames=[autoscalingName]
        )
    if response['AutoScalingGroups']:
        for AutoScalingGroup in response['AutoScalingGroups']:
            if AutoScalingGroup and AutoScalingGroup["AutoScalingGroupName"] == autoscalingName:
                print(f"Auto scaling group '{autoscalingName}' already exists.")
                return True
    print("Auto scaling not found..")
    return False
        
def create_autoscaling(autoscaling, target_group_arn, autoscalingName, launch_configuration_name, subnet_ids):
    try:    
        vpc_zone_identifier = ','.join(subnet_ids)
        response = autoscaling.create_auto_scaling_group(
            AutoScalingGroupName=autoscalingName,
            LaunchConfigurationName=launch_configuration_name,
            MinSize=1,
            MaxSize=3,
            DesiredCapacity=1,
            VPCZoneIdentifier=vpc_zone_identifier,
            TargetGroupARNs=[target_group_arn],
            Tags=[
                {
                    'ResourceId': autoscalingName,
                    'ResourceType': 'auto-scaling-group',
                    'Key': 'Name',
                    'Value': autoscalingName,
                    'PropagateAtLaunch': True
                },
            ]
        )
        print(response)

        print('Created auto scaling group')
        return response
    except Exception as e:
        print(f"An error occurred: {e}")
        return None

def check_scaling_policy_existence(autoscaling,asg_name, policy_name):
    response = autoscaling.describe_policies(
        AutoScalingGroupName=asg_name,
        PolicyNames=[policy_name]
    )
    if response['ScalingPolicies']:
        for policy in response['ScalingPolicies']:
            if policy and policy["PolicyName"] == policy_name:
                return True
    return False

def create_scaling_policy(autoscaling, autoscalingName, policyName):
    try:
        response = autoscaling.put_scaling_policy(
                AutoScalingGroupName=autoscalingName,
                PolicyName=policyName,
                PolicyType='TargetTrackingScaling',
                TargetTrackingConfiguration={
                    'PredefinedMetricSpecification': {
                        'PredefinedMetricType': 'ASGAverageCPUUtilization'
                    },
                    'TargetValue': 50.0  
                }
            )
        return response 
    except:
        return None

def main():
    try:
        required_ports = {22, 443, 80}
        key_pair_name = 'monitoring_ec2'
        ami_name='AMIImageofwebserver'
        lb_name='monitoring-load-balancing'
        autoscalingName="monitoringautoscale"
        policyName="monitroingploicy"
        launch_configuration_name="monitoring_launch_configuration"
        
        session = boto3.Session(profile_name='profile1', region_name="ap-northeast-2")
        ec2_client = session.client('ec2')
        elbv2_client = session.client('elbv2')
        autoscaling = session.client('autoscaling')

        vpc_id, sg_id, current_ports = get_default_vpc_id(ec2_client)

        if not vpc_id:
            print("Default VPC not found. Creating..")
            vpc_id = create_vpc(ec2_client)

        if not sg_id:
            print("Security group not found. Creating...")
            sg_id = create_security_group(ec2_client, vpc_id)
        
        update_default_security_group(ec2_client, required_ports, current_ports, sg_id)

        with open('./userdata.sh', 'r') as userdata_file:
            user_data_script = userdata_file.read()

        subnet_id = get_subnet_id(ec2_client, vpc_id)

        primary_instance_id = check_ec2_instance(ec2_client, servername='primaryserver')
        if primary_instance_id is None:
            print("Primary server instance not found. Creating one..")
            create_key_pair(ec2_client, key_pair_name)
            ami_image_id = fetch_ami_id(ec2_client)
            if ami_image_id is None:
                print("AMI ID not found")
                return
            primary_instance_id = create_ec2_instance(ec2_client, key_pair_name, sg_id, ami_image_id, user_data_script, subnet_id, servername='primaryserver')
            if primary_instance_id is not None:
                print(f"Primary server created: {primary_instance_id}")
                print("Waiting for the instance to be up and UserData to execute...")
                time.sleep(420)
                ami_id = create_ami(ec2_client, primary_instance_id, ami_name)
                waiter = ec2_client.get_waiter('image_available')
                print("Waiting for AMI to become available...")
                waiter.wait(ImageIds=[ami_id])
                print(f"AMI {ami_id} is now available.")
        else:
            ami_id = check_mern_ami(ec2_client, ami_name)
            if ami_id is None:
                ami_id = create_ami(ec2_client, primary_instance_id, ami_name)
                waiter = ec2_client.get_waiter('image_available')
                print("Waiting for AMI to become available...")
                waiter.wait(ImageIds=[ami_id])
                print(f"AMI {ami_id} is now available.")

        secondary_instance_id = check_ec2_instance(ec2_client, servername='secondaryserver')
        if secondary_instance_id is None:
            print("Secondary server instance not found. Creating one..")
            secondary_instance_id = create_ec2_instance(ec2_client, key_pair_name, sg_id, ami_id, user_data_script, subnet_id, servername='secondaryserver')
            if secondary_instance_id is not None:
                print(f"Secondary server created: {secondary_instance_id}")
                print("Waiting for the instance to be up and UserData to execute...")
                time.sleep(420)

        target_group_arn = create_target_group_with_instances(elbv2_client, 'MyTargetGroup', vpc_id, 'HTTP', 80, [primary_instance_id, secondary_instance_id])
        if target_group_arn is None:
            print("Failed to create target group.")

        load_balancing_arn = check_load_balancer_exists(elbv2_client, lb_name)
        print(load_balancing_arn)
        if load_balancing_arn is None:
            subnets = get_subnet_ids_for_vpc(ec2_client,vpc_id)
            if len(subnets) < 2:
                cidr_block = "192.169.{}.0/24"
                print("VPC has less than 2 subnets. Cannot create load balancer.")
                subnet_id = create_subnet(ec2_client, vpc_id, cidr_block)
                print(subnet_id)
            load_balancing_arn = create_load_balancer(elbv2_client, lb_name, subnet_id, sg_id)

        if load_balancing_arn is not None:
            listener_arn = check_listener_exists(elbv2_client, load_balancing_arn)
            if listener_arn is None:
                listener_arn = create_listener(elbv2_client, load_balancing_arn, target_group_arn)
        else:
            print("Failed to create load balancer.")

        launch_config_exists = check_launch_configuration(autoscaling, launch_configuration_name)
        if not launch_config_exists:
            print("Creating launch configuration...")
            launch_configuration_arn = create_launch_configuration(autoscaling, launch_configuration_name, ami_id, key_pair_name, sg_id, user_data_script)
            if launch_configuration_arn is None or launch_configuration_arn["ResponseMetadata"]["HTTPStatusCode"] != 200:
                print("Failed to create launch configuration.")

        autoscaling_exists = check_autoscaling(autoscaling, autoscalingName)
        if not autoscaling_exists:
            subnets = get_subnet_ids_for_vpc(ec2_client,vpc_id)
            response_autoscaling = create_autoscaling(autoscaling, target_group_arn, autoscalingName, launch_configuration_name, subnets)
            if response_autoscaling is None:
                print("Failed to create autoscaling group.")

        scaling_policy_exists = check_scaling_policy_existence(autoscaling, autoscalingName, policyName)
        if not scaling_policy_exists:
            response_scaling_policy = create_scaling_policy(autoscaling, autoscalingName, policyName)
            if response_scaling_policy is None:
                print("Failed to create scaling policy.")
        # Final_json = {}
        # Final_json["primary_instance_id"] = primary_instance_id
        # Final_json["secondary_instance_id"] = secondary_instance_id
        # Final_json["load_balancing_arn"] = load_balancing_arn
        # Final_json["target_group_arn"] = target_group_arn
        # Final_json["listener_arn"] = listener_arn
        # Final_json["launch_configuration_arn"] = launch_configuration_arn
        # Final_json["autoscalingName"] = autoscalingName
        # Final_json["autoscaling_arn"] = response_autoscaling
        # Final_json["scaling_policy_arn"] = response_scaling_policy
        # Final_json["policyName"] = policyName
        # Final_json['VPC_id'] = vpc_id
        # print(Final_json)


    except ClientError as e:
        print(f"An error occurred: {e}")

if __name__ == "__main__":
    main()

