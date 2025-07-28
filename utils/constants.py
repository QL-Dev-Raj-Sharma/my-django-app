from django.conf import settings

class Constant:
    django_default_codes = {
        "required": 508,
        "blank": 508,
        "null": 508,
        "empty": 508,
    }

    response_messages = {
        124: "OTP sent successfully",
        125: "OTP verified successfully",
        138: "Registration completed successfully",
        139: "Login successful",
        140: "Password changed successfully",
        141: "Password reset successfully",
        142: "Profile fetched successfully",
        143: "Profile updated successfully",
        144: "Public profile fetched successfully",
        303: "User deleted successfully",

        102: "Invalid credentials",
        117: "OTP expired or invalid",
        118: "Invalid OTP",
        134: "Username already exists",
        135: "Email already exists",
        136: "Phone number already exists",
        137: "Invalid Indian phone number format",
        151: "Identifier is required",
        152: "Password is required",
        154: "Passwords do not match",
        155: "Invalid old password",
        156: "Email not found",
        157: "User not found",
        701: "Username required",
        702: "Email required",
        
        508: "A required parameter or value is missing",
        101: "User not found",
        103: "User account is inactive",
        509: "Invalid or expired token",
    }