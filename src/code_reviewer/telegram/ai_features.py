"""
AI-powered code features for Telegram bot.
"""

from typing import Optional


# Language-specific templates
CODE_TEMPLATES = {
    # Python templates
    "python": {
        "print": 'print("Hello, World!")',
        "hello": 'print("Hello, World!")',
        "سلام": 'print("سلام دنیا!")',
        "bye": 'print("Goodbye!")',
        "خداحافظ": 'print("خداحافظ!")',
        "رندوم": '''import random

# تولید عدد رندوم
random_number = random.randint(1, 100)
print(f"عدد رندوم: {random_number}")

# رندوم از یک لیست
colors = ["قرمز", "آبی", "سبز", "زرد"]
random_color = random.choice(colors)
print(f"رنگ رندوم: {random_color}")

# ترتیب رندوم
numbers = [1, 2, 3, 4, 5]
random.shuffle(numbers)
print(f"ترتیب رندوم: {numbers}")''',
        "عدد": '''import random

# تولید عدد رندوم
random_number = random.randint(1, 100)
print(f"عدد رندوم: {random_number}")

# عدد رندوم اعشاری
random_float = random.random()
print(f"عدد اعشاری رندوم: {random_float}")''',
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
        "لیست": '''# ایجاد لیست
numbers = [1, 2, 3, 4, 5]

# نمایش لیست
print("لیست اعداد:", numbers)

# پیدا کردن بزرگترین
print("بزرگترین:", max(numbers))

# پیدا کردن کوچکترین
print("کوچکترین:", min(numbers))

# مجموع
print("مجموع:", sum(numbers))''',
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
    print("صفر است")''',
        "کلاس": '''class Person:
    """کلاس شخص"""
    
    def __init__(self, name, age):
        self.name = name
        self.age = age
    
    def greet(self):
        return "سلام، من " + self.name + " هستم"
    
    def is_adult(self):
        return self.age >= 18

# استفاده
person = Person("محمد", 25)
print(person.greet())''',
    },
    
    # C templates
    "c": {
        "print": '#include <stdio.h>\n\nint main() {\n    printf("Hello, World!\\n");\n    return 0;\n}',
        "hello": '#include <stdio.h>\n\nint main() {\n    printf("Hello, World!\\n");\n    return 0;\n}',
        "سلام": '#include <stdio.h>\n\nint main() {\n    printf("سلام دنیا!\\n");\n    return 0;\n}',
        "bye": '#include <stdio.h>\n\nint main() {\n    printf("Goodbye!\\n");\n    return 0;\n}',
        "خداحافظ": '#include <stdio.h>\n\nint main() {\n    printf("خداحافظ!\\n");\n    return 0;\n}',
        "ماشین حساب": '''#include <stdio.h>

int main() {
    float num1, num2, result;
    char op;
    
    printf("ماشین حساب ساده\\n");
    print("عملیات: +, -, *, /\\n");
    
    printf("عدد اول: ");
    scanf("%f", &num1);
    
    printf("عملگر: ");
    scanf(" %c", &op);
    
    printf("عدد دوم: ");
    scanf("%f", &num2);
    
    switch(op) {
        case '+':
            result = num1 + num2;
            break;
        case '-':
            result = num1 - num2;
            break;
        case '*':
            result = num1 * num2;
            break;
        case '/':
            if(num2 != 0)
                result = num1 / num2;
            else {
                printf("خطا: تقسیم بر صفر\\n");
                return 1;
            }
            break;
        default:
            printf("عملگر نامعتبر\\n");
            return 1;
    }
    
    printf("نتیجه: %.2f\\n", result);
    return 0;
}''',
        "فیبوناچی": '''#include <stdio.h>

void fibonacci(int n) {
    int a = 0, b = 1, temp;
    
    printf("فیبوناچی: ");
    for(int i = 0; i < n; i++) {
        printf("%d ", a);
        temp = a + b;
        a = b;
        b = temp;
    }
    printf("\\n");
}

int main() {
    fibonacci(10);
    return 0;
}''',
    },
    
    # JavaScript templates
    "javascript": {
        "print": 'console.log("Hello, World!");',
        "hello": 'console.log("Hello, World!");',
        "سلام": 'console.log("سلام دنیا!");',
        "bye": 'console.log("Goodbye!");',
        "خداحافظ": 'console.log("خداحافظ!");',
        "ماشین حساب": '''// Simple Calculator
function calculator(num1, op, num2) {
    switch(op) {
        case '+': return num1 + num2;
        case '-': return num1 - num2;
        case '*': return num1 * num2;
        case '/': return num2 !== 0 ? num1 / num2 : "خطا: تقسیم بر صفر";
        default: return "عملگر نامعتبر";
    }
}

// Example usage
console.log("نتیجه:", calculator(10, '+', 5));  // 15
console.log("نتیجه:", calculator(10, '*', 3));  // 30''',
    },
    
    # Java templates
    "java": {
        "print": '''public class Main {
    public static void main(String[] args) {
        System.out.println("Hello, World!");
    }
}''',
        "hello": '''public class Main {
    public static void main(String[] args) {
        System.out.println("Hello, World!");
    }
}''',
        "سلام": '''public class Main {
    public static void main(String[] args) {
        System.out.println("سلام دنیا!");
    }
}''',
    },
    
    # C++ templates
    "cpp": {
        "print": '#include <iostream>\n\nint main() {\n    std::cout << "Hello, World!" << std::endl;\n    return 0;\n}',
        "hello": '#include <iostream>\n\nint main() {\n    std::cout << "Hello, World!" << std::endl;\n    return 0;\n}',
        "سلام": '#include <iostream>\n\nint main() {\n    std::cout << "سلام دنیا!" << std::endl;\n    return 0;\n}',
    },
    
    # Go templates
    "go": {
        "print": 'package main\n\nimport "fmt"\n\nfunc main() {\n    fmt.Println("Hello, World!")\n}',
        "hello": 'package main\n\nimport "fmt"\n\nfunc main() {\n    fmt.Println("Hello, World!")\n}',
        "سلام": 'package main\n\nimport "fmt"\n\nfunc main() {\n    fmt.Println("سلام دنیا!")\n}',
    },
    
    # Rust templates
    "rust": {
        "print": 'fn main() {\n    println!("Hello, World!");\n}',
        "hello": 'fn main() {\n    println!("Hello, World!");\n}',
        "سلام": 'fn main() {\n    println!("سلام دنیا!");\n}',
    },
}


def detect_language(text: str) -> str:
    """
    Detect programming language from Persian text.
    
    Args:
        text: Persian text describing the language
        
    Returns:
        Language name
    """
    text_lower = text.lower()
    
    # Check for C++ first (before C)
    if any(word in text_lower for word in ["پلاس", "++", "cpp", "سی پلاس"]):
        return "cpp"
    
    # Check for C
    if any(word in text_lower for word in ["سی ", "زبان c", " به c", " به سی"]):
        return "c"
    
    # Check for JavaScript (before Java!)
    if any(word in text_lower for word in ["جاسکریپت", "javascript", "js", "جاوااسکریپت", "جاوا اسکریپت"]):
        return "javascript"
    
    # Check for Java
    if any(word in text_lower for word in ["جاوا", "java"]):
        return "java"
    
    # Check for Go
    if any(word in text_lower for word in ["گو", "go", "گولنگ"]):
        return "go"
    
    # Check for Rust
    if any(word in text_lower for word in ["راست", "rust"]):
        return "rust"
    
    # Check for Python
    if any(word in text_lower for word in ["پایتون", "python", "پیتون"]):
        return "python"
    
    # Default to Python
    return "python"


def generate_code_from_persian(description: str) -> Optional[str]:
    """
    Generate code based on Persian description.
    
    Args:
        description: Persian description of what to build
        
    Returns:
        Generated code or None if not understood
    """
    description_lower = description.lower()
    
    # Detect target language
    target_lang = detect_language(description)
    
    # Get templates for the target language
    templates = CODE_TEMPLATES.get(target_lang, CODE_TEMPLATES["python"])
    
    # Check for specific requests
    for keyword, code in templates.items():
        if keyword in description_lower:
            return code
    
    # Check for print requests
    if any(word in description_lower for word in ["چاپ", "print", "نمایش"]):
        if "hello" in description_lower:
            return templates.get("hello", templates.get("print"))
        elif "سلام" in description_lower:
            return templates.get("سلام", templates.get("print"))
        elif "bye" in description_lower or "خداحافظ" in description_lower:
            return templates.get("bye", templates.get("print"))
        else:
            return templates.get("print")
    
    # Check for function requests
    if any(word in description_lower for word in ["تابع", "function", "تعریف"]):
        if "فیبوناچی" in description_lower or "fibonacci" in description_lower:
            return templates.get("فیبوناچی")
        elif "ماشین حساب" in description_lower or "calculator" in description_lower:
            return templates.get("ماشین حساب")
    
    # Default: try to find any matching template
    for keyword, code in templates.items():
        if keyword in description_lower:
            return code
    
    # Final fallback
    return templates.get("print", templates.get("hello"))


def translate_code(code: str, target_lang: str = "javascript") -> str:
    """
    Translate code between languages (simple translation).
    
    Args:
        code: Source code
        target_lang: Target language
        
    Returns:
        Translated code
    """
    # Simple translation mappings
    translations = {
        "python_to_javascript": {
            "def ": "function ",
            "print(": "console.log(",
            "#": "//",
            "True": "true",
            "False": "false",
            "None": "null",
            "elif": "else if",
            "self": "this",
            "True": "true",
            "False": "false",
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
        "python_to_c": {
            "def ": "void ",
            "print(": "printf(",
            "#": "//",
            "True": "1",
            "False": "0",
            "None": "NULL",
            "self": "this",
        },
    }
    
    result = code
    
    if target_lang.lower() in ["javascript", "js"]:
        for py, js in translations["python_to_javascript"].items():
            result = result.replace(py, js)
    elif target_lang.lower() in ["java"]:
        for py, java in translations["python_to_java"].items():
            result = result.replace(py, java)
    elif target_lang.lower() in ["c"]:
        for py, c in translations["python_to_c"].items():
            result = result.replace(py, c)
    
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
        
        if not line or line.startswith('#') or line.startswith('//'):
            continue
        
        if line.startswith('def '):
            func_name = line.split('(')[0].replace('def ', '')
            explanations.append("خط " + str(i) + ": تابع '" + func_name + "' تعریف شده")
        elif line.startswith('class '):
            class_name = line.split(':')[0].replace('class ', '')
            explanations.append("خط " + str(i) + ": کلاس '" + class_name + "' تعریف شده")
        elif line.startswith('import ') or line.startswith('#include'):
            explanations.append("خط " + str(i) + ": یک کتابخانه وارد شده")
        elif line.startswith('if ') or line.startswith('switch'):
            explanations.append("خط " + str(i) + ": یک شرط بررسی میشه")
        elif line.startswith('for ') or line.startswith('while'):
            explanations.append("خط " + str(i) + ": یک حلقه شروع میشه")
        elif 'print(' in line or 'printf(' in line or 'console.log(' in line or 'System.out.println(' in line:
            explanations.append("خط " + str(i) + ": یک متن چاپ میشه")
        elif '=' in line and not line.startswith('==') and not line.startswith('!='):
            explanations.append("خط " + str(i) + ": یک متغیر تعریف یا تغییر میکنه")
    
    if not explanations:
        return "این کد شامل " + str(len(lines)) + " خط هست"
    
    return "\\n".join(explanations)
