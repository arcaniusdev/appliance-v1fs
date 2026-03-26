FROM public.ecr.aws/lambda/python:3.12

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY handler.py cfn_response.py ssh_helper.py cert_extractor.py ./

CMD ["handler.handler"]
