import subprocess
from openpyxl import Workbook


def get_scheduled_tasks():
    try:
        output = subprocess.check_output('schtasks /query /fo LIST', shell=True, universal_newlines=True)

        tasks = output.strip().split('\n\n')

        task_details = []

        for task in tasks:
            lines = task.split('\n')
            details = {}

            for line in lines:
                if ':' in line:
                    key, value = line.split(':', 1)
                    details[key.strip()] = value.strip()

            task_details.append(details)

        return task_details

    except subprocess.CalledProcessError:
        print("Failed to fetch scheduled tasks.")


scheduled_tasks = get_scheduled_tasks()


all_workbook = Workbook()
all_sheet = all_workbook.active

all_headers = ['Task Name', 'Description', 'Status', 'Last Run Time', 'Next Run Time']
all_sheet.append(all_headers)


filtered_workbook = Workbook()
filtered_sheet = filtered_workbook.active

filtered_headers = ['Task Name', 'Description', 'Status', 'Last Run Time', 'Next Run Time']
filtered_sheet.append(filtered_headers)

with open('input.txt', 'r') as file:
    exclude_words = [word.strip() for word in file.readlines()]

for task in scheduled_tasks:
    task_name = task.get('TaskName', 'N/A')

    
    all_row = [
        task_name,
        task.get('Description', 'N/A'),
        task.get('Status', 'N/A'),
        task.get('Last Run Time', 'N/A'),
        task.get('Next Run Time', 'N/A')
    ]
    all_sheet.append(all_row)

    
    exclude_task = False
    for word in exclude_words:
        if word in task_name:
            exclude_task = True
            break
    if not exclude_task:
        filtered_row = [
            task_name,
            task.get('Description', 'N/A'),
            task.get('Status', 'N/A'),
            task.get('Last Run Time', 'N/A'),
            task.get('Next Run Time', 'N/A')
        ]
        filtered_sheet.append(filtered_row)


all_workbook.save('all_scheduled_tasks.xlsx')
filtered_workbook.save('filtered_tasks.xlsx')
