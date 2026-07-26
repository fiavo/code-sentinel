"""
AI-powered code features for Telegram bot.
"""

from typing import Optional


# Pre-defined responses for common Persian requests
CODE_TEMPLATES = {
    # Print statements
    "چاپ": 'print("Hello, World!")',
    "hello": 'print("Hello, World!")',
    "سلام": 'print("سلام دنیا!")',
    
    # Simple functions
    "فیبوناچی": '''def fibonacci(n):
    """Calculate Fibonacci sequence"""
    if n <= 0:
        return []
    elif n == 1:
        return [0]
    
    fib = [0, 1]
    for i in range(2, n):
        fib.append(fib[i-1] + fib[i-2])
    return fib

# Example: Get first 10 Fibonacci numbers
print(fibonacci(10))''',
    
    "ماشین حساب": '''def calculator():
    """Simple calculator"""
    print("ماشین حساب ساده")
    print("عملیات: +, -, *, /")
    
    num1 = float(input("عدد اول: "))
    op = input("عملگر: ")
    num2 = float(input("عدد دوم: "))
    
    if op == '+':
        result = num1 + num2
    elif op == '-':
        result = num1 - num2
    elif op == '*':
        result = num1 * num2
    elif op == '/':
        result = num1 / num2 if num2 != 0 else "خطا: تقسیم بر صفر"
    else:
        result = "عملگر نامعتبر"
    
    print("نتیجه:", result)

calculator()''',
    
    "لیست": '''# ایجاد لیست
numbers = [1, 2, 3, 4, 5]

# نمایش لیست
print("لیست اعداد:", numbers)

# پیدا کردن بزرگترین
print("بزرگترین:", max(numbers))

# پیدا کردن کوچکترین
print("کوچکترین:", min(numbers))

# مجموع
print("مجموع:", sum(numbers))

# مرتب سازی
sorted_numbers = sorted(numbers, reverse=True)
print("مرتب شده (نزولی):", sorted_numbers)''',
    
    "حلقه": '''# حلقه for
print("حلقه for:")
for i in range(1, 6):
    print("عدد:", i)

print("\\nحلقه while:")
# حلقه while
count = 1
while count <= 5:
    print("شمارنده:", count)
    count += 1''',
    
    "شرط": '''# شرط if/else
number = 10

if number > 0:
    print(number, "مثبت است")
elif number < 0:
    print(number, "منفی است")
else:
    print("صفر است")

# شرط پیچیده
age = 25
if age >= 18:
    print("بزرگسال")
else:
    print("کودک")''',
    
    "کلاس": '''class Person:
    """کلاس شخص"""
    
    def __init__(self, name, age):
        self.name = name
        self.age = age
    
    def greet(self):
        return "سلام، من " + self.name + " هستم و " + str(self.age) + " سال دارم"
    
    def is_adult(self):
        return self.age >= 18

# استفاده
person = Person("محمد", 25)
print(person.greet())
print("بزرگسال:", person.is_adult())''',
    
    "فایل": '''# خواندن فایل
def read_file(filename):
    try:
        with open(filename, 'r', encoding='utf-8') as file:
            content = file.read()
            return content
    except FileNotFoundError:
        return "فایل پیدا نشد"

# نوشتن فایل
def write_file(filename, content):
    with open(filename, 'w', encoding='utf-8') as file:
        file.write(content)
    print("فایل", filename, "ذخیره شد")

# مثال
write_file("test.txt", "سلام دنیا")
print(read_file("test.txt"))''',
    
    "اتصال": """# اتصال به دیتابیس (مثال ساده)
import sqlite3

def create_database():
    conn = sqlite3.connect('example.db')
    cursor = conn.cursor()
    
    # ایجاد جدول
    cursor.execute('CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, name TEXT, email TEXT)')
    
    # اضافه کردن داده
    cursor.execute("INSERT INTO users (name, email) VALUES (?, ?)", 
                   ("محمد", "mohammad@example.com"))
    
    conn.commit()
    conn.close()
    print("دیتابیس ایجاد شد")

create_database()""",
}

# Translation templates
TRANSLATION_TEMPLATES = {
    "python_to_javascript": {
        "def ": "function ",
        "print(": "console.log(",
        "#": "//",
        "True": "true",
        "False": "false",
        "None": "null",
        "elif": "else if",
        "self": "this",
    },
    "python_to_java": {
        "def ": "public static void ",
        "print(": "System.out.println(",
        "#": "//",
        "True": "true",
        "False": "false",
        "None": "null",
        "self": "this",
    },
}


def generate_code_from_persian(description: str) -> Optional[str]:
    """
    Generate code based on Persian description.
    
    Args:
        description: Persian description of what to build
        
    Returns:
        Generated code or None if not understood
    """
    description_lower = description.lower()
    
    # Check for specific requests
    for keyword, code in CODE_TEMPLATES.items():
        if keyword in description_lower:
            return code
    
    # Check for print requests
    if any(word in description_lower for word in ["چاپ", "print", "نمایش"]):
        if "hello" in description_lower:
            return 'print("Hello, World!")'
        elif "سلام" in description_lower:
            return 'print("سلام دنیا!")'
        else:
            return 'print("Hello, World!")'
    
    # Check for function requests
    if any(word in description_lower for word in ["تابع", "function", "تعریف"]):
        if "فیبوناچی" in description_lower or "fibonacci" in description_lower:
            return CODE_TEMPLATES["فیبوناچی"]
        elif "ماشین حساب" in description_lower or "calculator" in description_lower:
            return CODE_TEMPLATES["ماشین حساب"]
    
    # Default: generate a simple hello world
    return '''# کد تولید شده بر اساس درخواست شما
# Generated code based on your request

print("Hello, World!")

# برای سفارشی کردن، درخواست دقیق‌تری بدید
# For customization, provide a more specific request'''


def translate_code(code: str, target_lang: str = "javascript") -> str:
    """
    Translate code between languages (simple translation).
    
    Args:
        code: Source code
        target_lang: Target language
        
    Returns:
        Translated code
    """
    result = code
    
    if target_lang.lower() in ["javascript", "js"]:
        for py, js in TRANSLATION_TEMPLATES["python_to_javascript"].items():
            result = result.replace(py, js)
    elif target_lang.lower() in ["java"]:
        for py, java in TRANSLATION_TEMPLATES["python_to_java"].items():
            result = result.replace(py, java)
    
    return result


def explain_code(code: str) -> str:
    """
    Generate explanation for code.
    
    Args:
        code: Code to explain
        
    Returns:
        Explanation in Persian
    """
    lines = code.strip().split('\n')
    
    explanations = []
    
    for i, line in enumerate(lines, 1):
        line = line.strip()
        
        if not line or line.startswith('#'):
            continue
        
        if line.startswith('def '):
            func_name = line.split('(')[0].replace('def ', '')
            explanations.append("خط " + str(i) + ": تابع '" + func_name + "' تعریف شده")
        elif line.startswith('class '):
            class_name = line.split(':')[0].replace('class ', '')
            explanations.append("خط " + str(i) + ": کلاس '" + class_name + "' تعریف شده")
        elif line.startswith('import '):
            explanations.append("خط " + str(i) + ": یک کتابخانه وارد شده")
        elif line.startswith('if '):
            explanations.append("خط " + str(i) + ": یک شرط بررسی میشه")
        elif line.startswith('for '):
            explanations.append("خط " + str(i) + ": یک حلقه شروع میشه")
        elif line.startswith('while '):
            explanations.append("خط " + str(i) + ": یک حلقه while شروع میشه")
        elif 'print(' in line:
            explanations.append("خط " + str(i) + ": یک متن چاپ میشه")
        elif '=' in line and not line.startswith('=='):
            explanations.append("خط " + str(i) + ": یک متغیر تعریف یا تغییر میکنه")
    
    if not explanations:
        return "این کد شامل " + str(len(lines)) + " خط هست"
    
    return "\\n".join(explanations)
