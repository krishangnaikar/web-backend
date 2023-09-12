# This is a sample Python script.
from urllib.parse import urlencode
# Press Shift+F10 to execute it or replace it with your code.
# Press Double Shift to search everywhere for classes, files, tool windows, actions, and settings.


def print_hi(name):
    # Use a breakpoint in the code line below to debug your script.
    print(f'Hi, {name}')  # Press Ctrl+F8 to toggle the breakpoint.
    REDIRECT_URI = 'http://localhost:8000/user/oauth'
    CLIENT_ID = "319958640423-lgkdd37i6d0eu4v983kvrnve8v6tugjl.apps.googleusercontent.com"
    scope = 'https://www.googleapis.com/auth/userinfo.profile https://www.googleapis.com/auth/userinfo.email https://www.googleapis.com/auth/user.organization.read https://www.googleapis.com/auth/contacts.readonly'

    auth_params = {
        'client_id' : CLIENT_ID,
        'redirect_uri' : REDIRECT_URI,
        'scope': f'{scope}',
        'response_type':'code',
        'access_type':'offline'

    }
    authorize_url = 'https://accounts.google.com/o/oauth2/auth'
    auth_url = f'{authorize_url}?{urlencode(auth_params)}'
    print(auth_url)
# Press the green button in the gutter to run the script.
if __name__ == '__main__':
    print_hi('PyCharm')

# See PyCharm help at https://www.jetbrains.com/help/pycharm/
