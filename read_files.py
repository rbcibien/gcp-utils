import os


def read_query(path, filename):
    query_path = os.path.join(path, filename)
    query = open(query_path, "r").read()
    return query.replace("\n", " ")
