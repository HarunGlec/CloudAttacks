import os
import time
import boto3
import json
import argparse

class TagFilter:
    def __init__(self, key, value):
        self.key = key
        self.value = value


def createInstance(session, tag_filter, key_name, security_group_id, image_id):
    ec2 = session.resource("ec2")
    instance = ec2.create_instances(
        ImageId=image_id,
        MinCount=1,
        MaxCount=1,
        InstanceType="t3.micro",
        KeyName=key_name,
        TagSpecifications=[
            {
                "ResourceType": "instance",
                "Tags": [
                    {"Key": tag_filter.key, "Value": tag_filter.value},
                ],
            }
        ],
        SecurityGroupIds=[
            security_group_id,
        ],
    )
    print(instance[0].id)


def createVolume(session, tag_filter):
    ec2 = session.resource("ec2")
    volume = ec2.create_volume(
        AvailabilityZone="eu-north-1a",
        Size=1,
        TagSpecifications=[
            {
                "ResourceType": "volume",
                "Tags": [
                    {"Key": tag_filter.key, "Value": tag_filter.value},
                ],
            }
        ],
    )
    print(volume.id)


def createSnapshot(session, tag_filter, volume_id):
    ec2 = session.resource("ec2")
    snapshot = ec2.create_snapshot(
        Description="This is a snapshot",
        VolumeId=volume_id,
        TagSpecifications=[
            {
                "ResourceType": "snapshot",
                "Tags": [
                    {"Key": tag_filter.key, "Value": tag_filter.value},
                ],
            }
        ],
    )
    print(snapshot.id)


def createS3Bucket(session, bucket_name):
    s3 = session.resource("s3")
    bucket = s3.create_bucket(
        Bucket=bucket_name,
        ACL="private",
        CreateBucketConfiguration={"LocationConstraint": "eu-north-1"},
    )
    print(bucket.name)


def putObjectToS3(session, bucket_name):
    s3 = session.resource("s3")
    obj = s3.Object(bucket_name, "test.txt")
    obj.put(Body=b"Hello World")


def s3FileUpload(session, bucket_name, local_path):
    client = session.client("s3")
    for filename in os.listdir(local_path):
        client.upload_file(local_path + filename, bucket_name, filename)


def createInstanceImage(session, tag_filter, instance_id):
    ec2 = session.client("ec2")
    image = ec2.create_image(
        InstanceId=instance_id,
        Name="HighValueImage",
        Description="This is a high value image",
        NoReboot=True,
        TagSpecifications=[
            {
                "ResourceType": "image",
                "Tags": [
                    {"Key": tag_filter.key, "Value": tag_filter.value},
                ],
            }
        ],
    )
    print(image["ImageId"])


def load_config_from_json(json_file):
    with open(json_file, "r") as f:
        return json.load(f)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="AWS Attack Simulator Recovery Script")

    parser.add_argument("--config", type=str, help="JSON config file path")

    parser.add_argument("--access_key", type=str, help="AWS Access Key ID")
    parser.add_argument("--secret_key", type=str, help="AWS Secret Access Key")
    parser.add_argument("--volume_id", type=str, help="Volume ID for Snapshot(e.g: vol-xxxx)")
    parser.add_argument("--instance_id", type=str, help="Instance ID for AMI(e.g: i-xxxx)")
    parser.add_argument("--image_id", type=str, help="Image ID for instance(e.g: ami-xxxx)")
    parser.add_argument("--security_group_id", type=str, help="Security group ID for instance(e.g: sg-xxxx)")
    parser.add_argument("--key_name", type=str, help="Key name for instance")
    parser.add_argument("--bucket_name", type=str, help="S3 Bucket name must have data prefix(e.g: dataXXX)")
    parser.add_argument("--file_path", type=str, help="Sample file directory to upload data bucket (e.g: /home/ec2-user/.../Logs/)")
    parser.add_argument("--log_path", type=str, help="Sample Log directory to upload log bucket (e.g: /home/ec2-user/.../Logs/)")


    args = parser.parse_args()

    config = {}
    if args.config:
        config = load_config_from_json(args.config)

    def get_param(name):
        return getattr(args, name) or config.get(name)

    try:
        ACCESS_KEY = get_param("access_key")
        SECRET_KEY = get_param("secret_key")

        if not ACCESS_KEY or not SECRET_KEY:
            try:
                ACCESS_KEY = os.environ["AWS_ACCESS_KEY_ID"]
                SECRET_KEY = os.environ["AWS_SECRET_ACCESS_KEY"]
            except KeyError:
                print("[!] Access key and secret key not provided - exiting")
                exit(1)

        session = boto3.Session(
            aws_access_key_id=ACCESS_KEY,
            aws_secret_access_key=SECRET_KEY,
        )

        tag_name = "Name"
        tag_value = "highValue"
        volume_id = get_param("volume_id")
        instance_id = get_param("instance_id")
        image_id = get_param("image_id")
        security_group_id = get_param("security_group_id")
        key_name = get_param("key_name")
        bucket_name = get_param("bucket_name")
        file_path = get_param("file_path")
        try:
            log_bucket = os.environ["LOG_BUCKET"]
        except KeyError:
            print("[!] OS environment variable 'LOG_BUCKET' must be set to use indicator removal technique")
        log_path = get_param("log_path")

        # -----Recovery functions-----
        createVolume(session, TagFilter(tag_name, tag_value))

        if key_name and security_group_id and image_id:
            createInstance(session, TagFilter(tag_name, tag_value), key_name, security_group_id, image_id)

        if volume_id:
            createSnapshot(session, TagFilter(tag_name, tag_value), volume_id)

        if instance_id:
            createInstanceImage(session, TagFilter(tag_name, tag_value), instance_id)

        if volume_id:
            time.sleep(90)
            createSnapshot(session, TagFilter(tag_name, tag_value + "2"), volume_id)
            createVolume(session, TagFilter(tag_name, tag_value + "2"))

        if bucket_name and file_path:
            s3FileUpload(session, bucket_name, file_path)

        if log_bucket:
            createS3Bucket(session, log_bucket)
            if log_path:
                s3FileUpload(session, log_bucket, log_path)
        # -----End of Recovery functions-----

    except Exception as e:
        with open("/home/ec2-user/aws_attack_simulator/recovery_error.txt", "a+") as f:
            f.write(str(e) + "\n")
        print("Error: " + str(e))
        pass

