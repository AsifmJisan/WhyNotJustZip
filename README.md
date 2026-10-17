# WhyNotJustZip

### Because apparently, a ZIP file wasn't complicated enough.

`WhyNotJustZip` is a gloriously unnecessary way to archive files. Instead of creating a normal archive, it generates a standalone script containing your files. Run that script later, enter your password, and it attempts to reconstruct the original files.

Yes, plenty of perfectly good archiving tools exist.

No, that didn't stop me.

## What does it do?

- **Turns files into scripts** — packages your selected files into a standalone Python or PowerShell restoration script.
- **Password protection** — encrypts the embedded archive data so the contents aren't stored as ordinary readable files in the generated script.
- **Restores files** — extracts the embedded data back into a directory.
- **Checks file integrity** — uses SHA-256 hashes to help detect corrupted or altered files.
- **Respects exclusions** — skips files and directories you don't want included.
- **Tries not to destroy your work** — refuses to overwrite existing files during restoration.
- **Works offline** — the generated script is designed to restore its contents without downloading the original files from somewhere else.

The exact features and compatibility depend on the generator version and the output format.

## Why?

Good question.

Maybe you want to carry a collection of files inside one script. Maybe you want a self-contained backup that doesn't depend on a separate archive file. Maybe you just want to see whether this ridiculous idea can work.

Whatever the reason, this project exists.

**This is not intended to replace conventional archiving software.** It explores an alternative approach to packaging and restoring files, with considerably more unnecessary scripting involved.

## Getting started

1. Download the generator script from the repository.
2. Run it using a compatible Python or PowerShell environment.
3. Select the files and directories you want to archive.
4. Configure the password and exclusions if supported by your version.
5. Generate the restoration script.
6. Keep the generated script somewhere safe.
7. When you need the files again, run the script in a compatible environment and follow its prompts.

The generated script is the archive. You don't need the original source directory to perform a restoration.

Consult the generator's help or prompts for the exact commands and options supported by your version.

## Compatibility

The project includes Python and PowerShell-related functionality.

- **Python:** designed around the Python standard library, with portability as a goal.
- **PowerShell:** intended for compatible Windows PowerShell environments.
- **Linux and macOS:** Python-based restoration may be suitable, depending on the version and platform.
- **Android:** Python-based restoration may be possible in Termux, depending on the generated script and its requirements.

Not every output format is guaranteed to work on every platform. Test a generated archive on the target environment before relying on it.

## Security disclaimer

Password protection is not a magical force field.

- Use a strong, unique password.
- Keep an independent copy of important files.
- Test restoration before deleting or moving the originals.
- Do not assume that a successful hash check proves the archive is trustworthy.
- Treat generated scripts as executable code. Inspect scripts from untrusted sources before running them.
- Do not use this project as your only backup for irreplaceable data.

The encryption and restoration implementation should be independently reviewed before being trusted with sensitive information. This project is not presented as a professionally audited security tool.

## Known limitations

- Generated scripts can be much larger and less convenient than ordinary archive files.
- Restoration requires a compatible runtime.
- Large archives may consume substantial memory, storage, or processing time, depending on the implementation.
- Ignore-file handling may not support every rule or syntax used by Git or Syncthing.
- Cross-platform behavior must be tested rather than assumed.
- A damaged or lost generated script may mean losing access to the files it contains.

And, of course, a normal ZIP archive is usually the more sensible choice.

## License

See the repository's `LICENSE` file for the applicable license.