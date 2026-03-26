# ADUC for Linux Help

## Getting Started

### Connect to your domain
1. Open **File > Connect**.
2. Enter your domain controller host and port.
3. Choose an authentication mode:
   - **Credentials**: username/password over LDAPS.
   - **Kerberos / SSO**: best for domain-joined machines with Kerberos configured.
4. Optionally save a profile and enable auto-connect.

## Main Layout

- **Left pane**: directory tree (domains, containers, OUs).
- **Right pane**: objects within the selected container.
- **Status bar**: object count, selection count, and current location.

## Searching

- Open search via:
  - **Action > Find...**
  - **Ctrl+F**
  - **F3**
- In the Find dialog:
  - Enter a search term (name, sAMAccountName, displayName, etc.).
  - Select **Find objects of type** to scope results.
  - Choose where to search from (**Search under**).
- If no matches are found, the app displays **No results found.**

## Common Object Tasks

- **Open Properties**: select one object and use **Properties** (or `Alt+Return`).
- **Rename**: select one object and press `F2`.
- **Delete**: select one or more objects and press `Delete`.
- **Create new objects**: use **Action** menu or context menu:
  - New User
  - New Group
  - New Computer
  - New Organizational Unit

## View and Navigation

- **Refresh**: `F5` or **View > Refresh**.
- **Advanced Features**: toggle in **View** menu to show additional details.
- Container objects can be expanded from the tree and context menus.

## Notes and Troubleshooting

- Ensure network connectivity to domain controllers.
- For some Samba AD environments, Kerberos bind may fail depending on runtime stack; use **Credentials** mode if needed.
- If a command fails due to permissions, verify your AD rights for the target object/container.

## Where settings are stored

- User settings are stored under:
  - `~/.config/aduc-linux/settings.json`
