import math
import re
import maskpass

class Prompt:
    @staticmethod
    def bool(prompt_text: str, default=True, truthy="y", falsy="n") -> bool:
        truthy = truthy.lower()
        falsy = falsy.lower()
        default_str = f"{truthy.upper()}/{falsy}" if default else f"{truthy}/{falsy.upper()}"
        
        choice = input(f"{prompt_text} ({default_str}): ").strip().lower()

        if choice == "":
            return default
        return choice == truthy

    @staticmethod
    def num(prompt_text: str, default: int, min: int = -math.inf, max: int = math.inf) -> int:
        prompt_text = f"{prompt_text} ({default})"
        if min != -math.inf:
            prompt_text += f" (Min: {min})"
        if max != math.inf:
            prompt_text += f" (Max: {max})"
        prompt_text += ": "
        while True:
            user_input = input(prompt_text).strip()
            if not user_input:
                return default
            try:
                value = int(user_input)
                if value < min or value > max:
                    print(f"Value must be between {min} and {max}.")
                else:
                    return value
            except ValueError:
                print("Please enter a valid integer.")

    @staticmethod
    def string(prompt_text: str, default: str) -> str:
        user_input = input(f"{prompt_text} (default: {default}): ").strip()
        return user_input if user_input else default
    
    @staticmethod
    def choice(prompt_text: str, default: int, *choices: str) -> int:
        # Display choices with numbers
        print(f"{prompt_text} (default: {default + 1})")
        for i, choice in enumerate(choices, start=1):
            print(f"  {i}. {choice}")

        while True:
            user_input = input(f"Enter choice [1-{len(choices)}]: ").strip()
            if not user_input:
                return default
            if user_input.isdigit():
                index = int(user_input) - 1
                # Index is between 0 and the amount of choices
                if 0 <= index < len(choices):
                    return index
            print("Invalid selection. Please choose a number from the list.")

    @staticmethod
    def password(prompt_text, paranoia: bool = False):
        while True:
            key = maskpass.askpass(prompt_text)
            if key:
                warnings = Prompt._check_password(key, paranoia)
                if Prompt.bool("Do you want to use the password? Or enter a new one", default= False if len(warnings) > 2 else True):
                    return key.encode()
                else:
                    print("Discarding password...")
            else:
                print("No password was entered! This will seriously undermine your security.")
                print("Keeping it empty can break functionality and will not be safely encrypted!")
                if Prompt.bool("Do you want to enter a new password? or keep it empty", True):
                    continue
                else: 
                    return ''
    
    @staticmethod
    def _check_password(password: str, paranoia: bool = False) -> None:
        warnings = []

        # Minimum length warnings
        min_len = 20 if paranoia else 14
        if len(password) < min_len:
            warnings.append(f"⚠️ Password is short, consider using atleast {min_len} characters.")

        # Character type checks (warn but don't block)
        if not re.search(r"[a-z]", password):
            warnings.append("• No lowercase letters.")
        if not re.search(r"[A-Z]", password):
            warnings.append("• No uppercase letters.")
        if not re.search(r"\d", password):
            warnings.append("• No numbers.")
        if not re.search(r"[!\"#$%&'()*+,-./:;<=>?@[\\\]^_`{|}~]", password):
            warnings.append("• No punctuation or symbols.")

        print("\n(⚠️) Password Warnings:")
        if warnings:
            for w in warnings:
                print(f"  {w}")
            print("  This password may be easier to guess or brute force.\n")
        else:
            print("  Perfect, can't see any issues!")
        return warnings
