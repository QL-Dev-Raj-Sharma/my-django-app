from django.conf import settings

class Constant:
    django_default_codes = {
        "required": 508,
        "blank": 508,
        "null": 508,
        "empty": 508,
    }

    response_messages = {

        #Registration and Login Codes

        101: "Registration completed successfully",
        102: "Invalid credentials",

        110: "Login successful",
        111: "User logout successfully",

        112: "Password changed successfully",
        113: "Password reset successfully",
        124: "Passwords do not match",
        125: "Password is required",
        126: "Invalid old password",

        114: "Profile fetched successfully",
        115: "Profile updated successfully",
        116: "User deleted successfully",
        117: "Invalid password",

        118: "User not found",

        119: "Email already exists",
        120: "Username already exists",
        121: "Phone number already exists",

        122: "Invalid phone number format",
        123: "Identifier is required",

        130: "Email not found",
        131: "Profile Fetched Succesfully",

        500: "Internal server error",
        501: "Page not found",
        502: "Invalid request format",
        504: "Authentication required",
        505: "Method not allowed",
        506: "Permission denied",
        507: "Validation error",
        508: "Required field missing",
        509: "Invalid or expired token",



        #otp related codes

        #success codes
        850: "OTP verified successfully",
        851: "OTP sent successfully",


        #error codes
        801: "OTP limit reached for today. Try again tomorrow.",
        802: "OTP already sent recently. Please wait before requesting again.",
        803: "OTP expired or invalid",
        804: "Invalid OTP",
        805: "This phone number is already in use by another account",


        #token related codes

        #error codes
        901: "Invalid token claims",
        902: "Token has expired",
        903: "Token invalidated",
        904: "Token has expired",
        905: "Invalid Token"


    }
