from google.cloud import bigquery


def get_last_modified_date(query, project_id, credentials, **kwargs):

    client = bigquery.Client(project=project_id, credentials=credentials)

    query_job = client.query(query)

    result = query_job.result()

    for row in result:
        last_modified_date = row[0]
        break

    kwargs["ti"].xcom_push(key="last_modified_date", value=last_modified_date)
