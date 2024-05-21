import os
import sys
import boto3
import random
import string
from concurrent.futures import ThreadPoolExecutor
import requests
import yaml

# 업로드 폴더를 지정해주세요
src_dir = sys.argv[1]

# 업로드할 버전을 지정해주세요 version
dst_dir = sys.argv[2]


def get_config(config_path):
    print(config_path)
    if os.path.isfile(config_path):
        print(f'{config_path} ok')
    else:
        print(f'{config_path} not found program shutdown')
        sys.exit(1)

    with open(config_path, 'r', encoding="UTF-8") as f:
        config = yaml.load(f,Loader=yaml.FullLoader)
    return config


def set_s3_client(access_key, secret_key, session_token):
    s3 = boto3.client(
        's3',
        aws_access_key_id=access_key,
        aws_secret_access_key=secret_key,
        aws_session_token=session_token,
    )
    return s3


def set_s3_resource(access_key, secret_key, session_token):
    s3 = boto3.resource(
        's3',
        aws_access_key_id=access_key,
        aws_secret_access_key=secret_key,
        aws_session_token=session_token,
    )
    return s3


def gscapi_post(url, jwt_token_pwd):
    headers = {
        'Content-Type': 'application/x-www-form-urlencoded'
    }
    sts_params = {
        'token': f'{jwt_token_pwd}'
    }
    response = requests.post(url, headers=headers, data=sts_params)
    try:
        response_data = response.json()
    except ValueError:
        raise ValueError("응답을 JSON으로 파싱할 수 없습니다.")

    if response.status_code == 200:
        if 'status' in response_data and response_data['status']:
            return response_data
        else:
            raise ValueError("API 호출 결과가 False입니다. 사용한 Token이 정상적인지 확인해주세요")
    else:
        raise ValueError(f"API 호출 실패: 상태 코드 {response.status_code}, 응답: {response.text}")


def upload_file_to_s3(s3, bucket, subdir, file, dst_dir, src_dir):
    full_path = os.path.join(subdir, file)
    # Convert path to Linux style
    full_path = full_path.replace("\\", "/")
    s3_path = dst_dir + "/" + full_path[len(src_dir):]
    # Remove unnecessary slash
    s3_path = s3_path.replace("//", "/")
    with open(full_path, 'rb') as data:
        s3.Bucket(bucket).put_object(Key=s3_path, Body=data)
    return s3_path


def upload_files_to_s3(s3_resource, src_dir, dst_dir, bucket):
    s3_paths = []

    # 랜덤 값을 붙이고 싶으면 아래 내용 주석 해제
    # random_str = ''.join(random.choices(string.ascii_uppercase + string.digits, k=15))

    with ThreadPoolExecutor() as executor:
        for subdir, dirs, files in os.walk(src_dir):
            for file in files:
                future = executor.submit(upload_file_to_s3, s3_resource, bucket, subdir, file, dst_dir, src_dir)
                s3_paths.append(future.result())
    return s3_paths, f"{dst_dir}/"


def list_files_in_bucket(s3_paths):
    for s3_path in s3_paths:
        print(s3_path)


# def delete_folder(s3_resource, bucket, folder_prefix):
#     s3_bucket = s3_resource.Bucket(bucket)
#     for obj in s3_bucket.objects.filter(Prefix=folder_prefix):
#         s3_resource.Object(bucket, obj.key).delete()


def s3_list_check(s3_client, bucket):
    response = s3_client.list_objects_v2(Bucket=bucket)

    # 중복된 폴더 이름을 제거하기 위한 집합
    top_folders = set()

    # 객체 목록에서 최상위 폴더만 추출
    if 'Contents' in response:
        for item in response['Contents']:
            key = item['Key']
            if '/' in key:
                folder = key.split('/')[0] + '/'
                top_folders.add(folder)

    # 최상위 폴더 목록 출력
    for folder in top_folders:
        print(folder)
    else:
        print(f"No objects in bucket {bucket}")



if __name__ == "__main__":
    base = os.path.dirname(os.path.abspath(__file__))
    config_path = f"{base}/.config/config.yaml"

    config = get_config(config_path)
    # 권한을 받아올 주소
    url = config['base']['url']
    # token 정보
    jwt_token_pwd = config['base']['token_pwd']

    # jwt decode 정보 얻어오기
    infos = gscapi_post(url, jwt_token_pwd)
    bucket = infos['bucket']
    arn = infos['arn']
    domain = infos['domain']
    access_key = infos['access_key']
    secret_key = infos['secret_key']
    session_token = infos['session_token']

    # s3 resource, client 자격증명 설정
    s3_resource = set_s3_resource(access_key, secret_key, session_token)
    s3_client = set_s3_client(access_key, secret_key, session_token)

    # s3에 폴더 업로드
    s3_paths, folder_prefix = upload_files_to_s3(s3_resource, src_dir, dst_dir, bucket)

    # s3에 업로드한 파일 리스트 출력
    list_files_in_bucket(s3_paths)

    # CDN 설정을 했다면 https 주소 출력
    cdn_url = f"{domain}{dst_dir}"

    print(f"""
    CDN URL:
    {cdn_url}""" )

    # # 업로드 완료된 s3 
    # s3_list_check(s3_client, arn, bucket)

    # # 폴더를 삭제하고 싶다면 아래 주석 해제
    # remove_dir = "data/tempfolder"
    # delete_folder(s3_resource, bucket, remove_dir)