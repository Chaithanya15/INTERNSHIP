import subprocess

input_file = "input.txt"
system_output_file = "system_output.txt"
application_output_file = "application_output.txt"
security_output_file = "security_output.txt"
filtered_application_output_file = "filtered_application_output.txt"
filtered_system_output_file = "filtered_system_output.txt"
filtered_security_output_file = "filtered_security_output.txt"
filter_file = "filter.txt"

with open(system_output_file, "w") as system_output, \
     open(application_output_file, "w") as application_output, \
     open(security_output_file, "w") as security_output:

    system_output.write("\n")
    application_output.write("\n")
    security_output.write("\n")

    with open(input_file, "r") as input_file:
        for line in input_file:
            event_id = line.strip().replace("Event Id=", "")

            if event_id == "":
                continue

            print("Event ID:", event_id)

            system_logs_found = False
            application_logs_found = False
            security_logs_found = False

            system_command = f'wevtutil qe System "/q:*[System/EventID={event_id}]" /f:text'
            try:
                system_logs = subprocess.check_output(system_command, shell=True, universal_newlines=True)
                if system_logs:
                    if "No events found" not in system_logs:
                        print(system_logs)
                        system_output.write(system_logs + "\n\n")
                        system_logs_found = True
            except subprocess.CalledProcessError:
                pass

            application_command = f'wevtutil qe Application "/q:*[System/EventID={event_id}]" /f:text'
            try:
                application_logs = subprocess.check_output(application_command, shell=True, universal_newlines=True)
                if application_logs:
                    print(application_logs)
                    application_output.write(application_logs + "\n\n")
                    application_logs_found = True
            except subprocess.CalledProcessError:
                pass

            security_command = f'wevtutil qe Security "/q:*[System/EventID={event_id}]" /f:text'
            try:
                security_logs = subprocess.check_output(security_command, shell=True, universal_newlines=True)
                if security_logs:
                    if "No events found" not in security_logs:
                        print(security_logs)
                        security_output.write(security_logs + "\n\n")
                        security_logs_found = True
            except subprocess.CalledProcessError:
                pass

            if not application_logs_found:
                print("---------------------------------------------")

            if not security_logs_found:
                print("---------------------------------------------")

# Filter logs based on Source Name
with open(filter_file, "r") as filter_input:
    source_names = [line.strip() for line in filter_input]

# Filter logs from application_output.txt
with open(application_output_file, "r") as application_logs, \
        open(filtered_application_output_file, "w") as filtered_application_output:
    skip_content = False
    skip_event_log = False
    for line in application_logs:
        if not skip_content:
            if any(source_name in line for source_name in source_names):
                skip_content = True
                skip_event_log = False
                if line.strip().startswith("Event[") or line.strip().startswith("Log :"):
                    skip_event_log = True
            else:
                filtered_application_output.write(line)
        else:
            if skip_event_log:
                if line.strip() == "":
                    skip_event_log = False
            else:
                if line.strip() == "":
                    skip_content =False

# Filter logs from system_output.txt
with open(system_output_file, "r") as system_logs, \
        open(filtered_system_output_file, "w") as filtered_system_output:
    skip_content = False
    skip_event_log = False
    for line in system_logs:
        if not skip_content:
            if any(source_name in line for source_name in source_names):
                skip_content = True
                skip_event_log = False
                if line.strip().startswith("Event[") or line.strip().startswith("Log :"):
                    skip_event_log = True
            else:
                filtered_system_output.write(line)
        else:
            if skip_event_log:
                if line.strip() == "":
                    skip_event_log = False
            else:
                if line.strip() == "":
                    skip_content = False

# Filter logs from security_output.txt
with open(security_output_file, "r") as security_logs, \
        open(filtered_security_output_file, "w") as filtered_security_output:
    skip_content = False
    skip_event_log = False
    for line in security_logs:
        if not skip_content:
            if any(source_name in line for source_name in source_names):
                skip_content = True
                skip_event_log = False
                if line.strip().startswith("Event[") or line.strip().startswith("Log :"):
                    skip_event_log = True
            else:
                filtered_security_output.write(line)
        else:
            if skip_event_log:
                if line.strip() == "":
                    skip_event_log = False
            else:
                if line.strip() == "":
                    skip_content = False

# Print filtered logs for each category
print("Filtered Application Logs:")
with open(filtered_application_output_file, "r") as filtered_application_output:
    print(filtered_application_output.read())

print("---------------------------------------------")

print("Filtered System Logs:")
with open(filtered_system_output_file, "r") as filtered_system_output:
    print(filtered_system_output.read())

print("---------------------------------------------")

print("Filtered Security Logs:")
with open(filtered_security_output_file, "r") as filtered_security_output:
    print(filtered_security_output.read())
