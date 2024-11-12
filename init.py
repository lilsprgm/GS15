def check_or_create_users_repo():
    # Define the directory name
    repo_name = "users"

    # Check if the directory exists
    if not os.path.exists(repo_name):
        # Create the directory if it doesn't exist
        os.makedirs(repo_name)
        print(f"The '{repo_name}' repository has been created.")
    else:
        print(f"The '{repo_name}' repository already exists.")
