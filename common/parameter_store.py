import os

import boto3


def parameter_data():
    """
    Create a connection with AWS Parameter Store and extract all the keys and values.

    Returns:
        dict: Dictionary of secret keys and values.

    Raises:
        Exception: Raises an exception if there is any error during the process.
    """
    try:
        # if  application running on local it will connect using access and secret key
        if os.getenv("environment") == "local":
            ssm_client = boto3.client("ssm", region_name=os.getenv("aws_secrete_manager_region"),
                                      aws_access_key_id=os.getenv("aws_access_key"),
                                      aws_secret_access_key=os.getenv("aws_secret_access_key"))
        else:
            ssm_client = boto3.client("ssm", region_name=os.getenv("aws_secrete_manager_region"))

        # NextToken:- While extracting values using path is there more value remains after extracting, then in response
        # we get NextToken parameter, which help to extract next remaining value
        # For very initial keeping it as a space ( )
        NextToken = " "
        final_dict = {}
        # Loop keep running until there is no value with respect to path
        while NextToken is not None:
            response = ssm_client.get_parameters_by_path(Path=os.getenv("parameter_store_path"), WithDecryption=True,
                                                         Recursive=True, MaxResults=10, NextToken=NextToken
                                                         )
            parameter_store = {}
            # Looping response parameter to extract only keys and values from response and
            # store it in any dictionary form
            for item in response["Parameters"]:
                key = item["Name"].split("/")[-1]
                value = item["Value"]
                parameter_store[key] = value

            final_dict.update(parameter_store)

            NextToken = response.get('NextToken', None)
        return final_dict

    except Exception:
        raise


def get_parameter_values():
    """
    Get a dictionary of secret keys and values.

    Returns:
        dict: Dictionary of secret keys and values.

    Raises:
        Exception: Raises an exception if there is any error during the process.
    """
    try:
        para_dict = parameter_data()
        return para_dict

    except Exception:
        raise
