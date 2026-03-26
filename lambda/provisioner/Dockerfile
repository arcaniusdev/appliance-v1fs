FROM public.ecr.aws/lambda/python:3.12

RUN dnf install -y awscli && dnf clean all

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY handler.py cfn_response.py ssh_helper.py cert_extractor.py eice_tunnel.py ./

CMD ["handler.handler"]
