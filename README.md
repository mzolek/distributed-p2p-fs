## Usage

The program accepts three arguments:

1. **Name** — the name visible to the server and other users.
2. **Port** — the port used by the client.
3. **Directory path** — the path to the directory shared with other users of the distributed file system.

For example:

```
go run client.go tree.go utils.go john 1234 ./directory
```

## User Interface

The user interface runs in the console. To start downloading data from another user or from the server, enter their name on a single line and press **Enter**.

For example, to download files from the server, enter:

```
galene.org
```

This downloads the filesystem shared by the server and saves it in the directory from which the program was started.

Information about errors and successful completion of communications is displayed in the console.
