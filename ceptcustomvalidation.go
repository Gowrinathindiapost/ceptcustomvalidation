package main

import (
	"regexp"
	"strconv"
	"time"

	"github.com/go-playground/validator/v10"
	//en_translations "github.com/go-playground/validator/v10/translations/en"
)

// Precompile the regex pattern globally
var (
	HOAPattern                                = regexp.MustCompile(`^\d{15}$`)
	PersonnelNamePattern                      = regexp.MustCompile(`^[A-Za-z][A-Za-z\s]{1,48}[A-Za-z]$`)
	AddressPattern                            = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9\s,.-]{1,48}[A-Za-z0-9]$`)
	EmailPattern                              = regexp.MustCompile(`^[a-zA-Z0-9._+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$`)
	gValidatePhoneLengthPattern               = regexp.MustCompile(`^\d{10}$`)
	allZerosRegex                             = regexp.MustCompile("^0+$")
	gValidateSOBONamePattern                  = regexp.MustCompile(`^[A-Za-z][A-Za-z\s]{1,48}[A-Za-z]$`)
	gValidatePANNumberPattern                 = regexp.MustCompile(`^[A-Z]{5}[0-9]{4}[A-Z]$`)
	gValidateVehicleRegistrationNumberPattern = regexp.MustCompile(`^[A-Z]{2}\d{2}[A-Z]{1,2}\d{4,7}$`)
	gValidateBarCodeNumberPattern             = regexp.MustCompile(`^[A-Z]{2}\d{6,12}[A-Z]{2}$`)
	alphanumericRegex                         = regexp.MustCompile(`^[A-Z0-9]+$`)
	trainNoPattern                            = regexp.MustCompile(`^\d{5}$`)
	customValidateGLCodePattern               = regexp.MustCompile(`^GL\d{11}$`)
	timeStampValidatePattern                  = regexp.MustCompile(`^(0[1-9]|[12][0-9]|3[01])-(0[1-9]|1[0-2])-(\d{4}) ([01]\d|2[0-3]):([0-5]\d):([0-5]\d)$`)
	customValidateAnyStringLengthto50Pattern  = regexp.MustCompile(`^[a-zA-Z][a-zA-Z0-9]{0,48}[a-zA-Z]$`)
	dateyyyymmddPattern                       = regexp.MustCompile(`^\d{4}-(0[1-9]|1[0-2])-(0[1-9]|[12]\d|3[01])$`)
	dateddmmyyyyPattern                       = regexp.MustCompile(`^(0[1-9]|[12][0-9]|3[01])-(0[1-9]|1[0-2])-\d{4}$`)
	validateEmployeeIDPattern                 = regexp.MustCompile(`^\d{8}$`)
	validateGSTINPattern                      = regexp.MustCompile(`^[0-9]{2}[A-Z]{5}[0-9]{4}[A-Z]{1}[A-Z0-9]{1}[Z]{1}[0-9]{1}$`)
	specialCharPattern                        = regexp.MustCompile(`[!@#$%^&*()<>:;"{}[\]\\]`)
	validateBankUserIDPattern                 = regexp.MustCompile(`^[A-Z0-9]{1,50}$`)
	validateOrderNumberPattern                = regexp.MustCompile(`^[A-Z]{2}\d{19}$`)
	validateAWBNumberPattern                  = regexp.MustCompile(`^[A-Z]{4}\d{9}$`)
	validatePNRNoPattern                      = regexp.MustCompile(`^[A-Z]{3}\d{6}$`)
	validatePLIIDPattern                      = regexp.MustCompile(`^[A-Z]{3}\d{10}$`)
	validatePaymentTransIDPattern             = regexp.MustCompile(`^\d{2}[a-fA-F0-9]{8}-[a-fA-F0-9]{4}-4[a-fA-F0-9]{3}-[89abAB][a-fA-F0-9]{3}-[a-fA-F0-9]{12}$`)
	validateOfficeCustomerIDPattern           = regexp.MustCompile(`^[a-zA-Z0-9\-]{1,50}$`)
	validateBankIDPattern                     = regexp.MustCompile(`^[A-Z0-9]{1,50}$`)
	validateCSIFacilityIDPattern              = regexp.MustCompile(`^[A-Z]{2}\d{11}$`)
	validatePosBookingOrderNumberPattern      = regexp.MustCompile(`^[A-Z]{2}\d{19}$`)
	validateSOLIDPattern                      = regexp.MustCompile(`^\d{6}\d{2}$`)
	validatePLIOfficeIDPattern                = regexp.MustCompile(`^[A-Z]{3}\d{10}$`)
	validateProductCodePattern                = regexp.MustCompile(`^[A-Z]{3}\d{12}$`)
	validateCustomerIDPattern                 = regexp.MustCompile(`^\d{10}$`)
	validateFacilityIDPattern                 = regexp.MustCompile(`^[A-Z]{2}\d{11}$`)
	validateApplicationIDPattern              = regexp.MustCompile(`^[A-Z]{3}\d{8}-\d{3}$`)
	validateReceiverKYCReferencePattern       = regexp.MustCompile(`^KYCREF[A-Z0-9]{0,44}$`)
	validateOfficeCustomerPattern             = regexp.MustCompile(`^[a-zA-Z0-9\s]+$`)
	validatePRANPattern                       = regexp.MustCompile(`^\d{12}$`)
)

// ValidateWithRegex is a common function that validates a string field against a provided regex pattern.
func ValidateWithGlobalRegex(fl validator.FieldLevel, regex *regexp.Regexp) bool {
	fieldValue := fl.Field().String()
	return regex.MatchString(fieldValue)
}

// ValidateHOA checks if the provided string is a valid HOA(Head Of Account). -- Check if Status is 15 digit numeric value.
func ValidateHOAPattern(fl validator.FieldLevel) bool {
	//pattern := `^\d{15}$`
	return ValidateWithGlobalRegex(fl, HOAPattern)
}

// ValidatePersonnelName checks if the provided string is a valid Personnel Name.
// Name should start with a letter and has a length between 3 and 50 characters
// 1 (first letter) + 1 (at least one middle character) + 1 (last letter) = 3 characters.
// 1 (first letter) + 48 (middle characters) + 1 (last letter) = 50 characters.
func ValidatePersonnelNamePattern(fl validator.FieldLevel) bool {
	//pattern := `^[A-Za-z][A-Za-z\s]{1,48}[A-Za-z]$`
	return ValidateWithGlobalRegex(fl, PersonnelNamePattern)
}

// ValidateAddress checks if the provided string is a valid address.
// Address should start with a letter and has a length between 3 and 50 characters
func ValidateAddressPattern(fl validator.FieldLevel) bool {
	//pattern := `^[A-Za-z0-9][A-Za-z0-9\s,.-]{1,48}[A-Za-z0-9]$`
	return ValidateWithGlobalRegex(fl, AddressPattern)
}

// ValidateEmail checks if the provided string is a valid email address.
// dot (.), underscore (_), plus (+), or hyphen (-) are allowed before @ symbol
// examples john.tom@example.com,user123@domain.co.uk,my-email@sub.domain.org
// user.name+tag+sorting@example.com,x@example.co,user_name@example-domain.com
// not accepted: user@domain,user@.com,@example.com,user@domain..com
func ValidateEmailPattern(fl validator.FieldLevel) bool {
	//pattern := `^[a-zA-Z0-9._+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$`

	return ValidateWithGlobalRegex(fl, EmailPattern)
}

// global validaton of phone length from library/template
func GValidatePhoneLengthPattern(fl validator.FieldLevel) bool {
	// Handle the case where the phone number is a string
	if _, ok := fl.Field().Interface().(string); ok {
		// Validate using a regular expression for exactly 10 digits
		// pattern := `^\d{10}$`
		// return ValidateWithRegex(fl, pattern)
		return ValidateWithGlobalRegex(fl, gValidatePhoneLengthPattern)
	}

	// Handle the case where the phone number is a uint64
	if phoneNumber, ok := fl.Field().Interface().(uint64); ok {
		// Check if the phone number has exactly 10 digits
		return phoneNumber >= 1000000000 && phoneNumber <= 9999999999
	}
	//works only for 64 bit system
	// Handle the case where the phone number is an int
	if phoneNumber, ok := fl.Field().Interface().(int); ok {
		// Check if the phone number has exactly 10 digits
		return phoneNumber >= 1000000000 && phoneNumber <= 9999999999
	}

	// If the field is neither a string, uint64, nor int, the validation fails
	return false
}

// GValidatePinCode is a global validator function that checks if the pincode has exactly 6 digits
// Not valid: 600000,601000,
func ValidatePinCodeGlobal(fl validator.FieldLevel) bool {
	zipCode := fl.Field().String()

	// Check if the length is 6
	if len(zipCode) != 6 {
		return false
	}
	// Check if the pin code contains only digits
	if _, err := strconv.Atoi(zipCode); err != nil {
		return false
	}

	// Check if the first digit is in the range 1 to 9
	firstDigit, err := strconv.Atoi(string(zipCode[0]))
	if err != nil || firstDigit < 1 || firstDigit > 9 {
		return false
	}

	// Check if the last five digits are not all zeros
	lastFiveDigits := zipCode[1:6]
	//allZerosRegex := regexp.MustCompile("^0+$")
	if allZerosRegex.MatchString(lastFiveDigits) {
		return false
	}
	// Check if the last three digits are not all zeros
	lastThreeDigits := zipCode[3:6]
	if allZerosRegex.MatchString(lastThreeDigits) {
		return false
	}
	return true

}

// GValidateSOBOName validates that the string starts and ends with a letter and has a length between 3 and 50 characters.
func GValidateSOBONamePattern(f1 validator.FieldLevel) bool {
	// Define the regex pattern
	// ^[A-Za-z] -> Start with a letter
	// [A-Za-z\s]{1,48} -> 1 to 48 letters or spaces
	// [A-Za-z]$ -> End with a letter
	//pattern := `^[A-Za-z][A-Za-z\s]{1,48}[A-Za-z]$`

	return ValidateWithGlobalRegex(f1, gValidateSOBONamePattern)
}

// GValidatePANNumber checks if the PAN number is in the correct format.
func GValidatePANNumberPattern(fl validator.FieldLevel) bool {
	// regex pattern for PAN number (5 letters followed by 4 digits followed by 1 letter)
	//pattern := `^[A-Z]{5}[0-9]{4}[A-Z]$`

	return ValidateWithGlobalRegex(fl, gValidatePANNumberPattern)
}

// GValidateVehicleRegistrationNumber checks if the vehicle registration number is in a valid format.
// "21BH4322AB" // Valid
// "KA02C1239"  // Valid
// "KA557738"   // Valid
// "MH12AB3456" // Valid
// "DL123AB456" // Invalid
// "KA@01C1234" // Invalid
// "MH12ABC1234" // Invalid
// "KA5678901" // Invalid
// "UP32XYZ"   // Invalid
func GValidateVehicleRegistrationNumberPattern(fl validator.FieldLevel) bool {
	// Define the regex pattern for vehicle registration number
	//pattern := `^[A-Z]{2}\d{2}[A-Z]{1,2}\d{4,7}$`
	return ValidateWithGlobalRegex(fl, gValidateVehicleRegistrationNumberPattern)
}

// ValidateBarCodeNumber checks if the registration number is in a valid format.
func GValidateBarCodeNumberPattern(fl validator.FieldLevel) bool {

	// Define the regex pattern for vehicle registration number
	//pattern := `^[A-Z]{2}\d{6,12}[A-Z]{2}$`
	return ValidateWithGlobalRegex(fl, gValidateBarCodeNumberPattern)
}

// CustomBagNumber validates if the bag number has exactly 29 characters, no special characters, and no lowercase letters.
func CustomBagNumberGlobal(fl validator.FieldLevel) bool {
	// Get the bag number from the field
	bagNumber, ok := fl.Field().Interface().(string)
	if !ok {
		// If it's not a string, the validation fails
		return false
	}
	// Check if the bag number has exactly 29 characters
	if len(bagNumber) < 13 {
		return false
	}
	// Check if the bag number contains only uppercase alphanumeric characters (no special characters, no lowercase letters)
	//alphanumericRegex := regexp.MustCompile(`^[A-Z0-9]+$`)

	return alphanumericRegex.MatchString(bagNumber)
}

// custome office id check if the officeId is between 7(1000000) and 8 digits(99999999)
//
//	func Customofficeid(fl validator.FieldLevel) bool {
//		// Get the officeId id from the field
//		officeId, ok := fl.Field().Interface().(int)
//		if !ok {
//			// If it's not a int, the validation fails
//			return false
//		}
//		return officeId >= 1000000 && officeId <= 99999999
//	}
func CustomofficeidGlobal(fl validator.FieldLevel) bool {
	// Handle the case where the officeId is an int
	if officeId, ok := fl.Field().Interface().(int); ok {
		return officeId >= 1000000 && officeId <= 99999999
	}

	// Handle the case where the officeId is a uint64
	if officeId, ok := fl.Field().Interface().(uint64); ok {
		return officeId >= 1000000 && officeId <= 99999999
	}

	// Handle the case where the officeId is a string
	if officeIdStr, ok := fl.Field().Interface().(string); ok {
		// Check if the string is not empty and contains only digits
		if len(officeIdStr) >= 7 && len(officeIdStr) <= 8 {
			if _, err := strconv.ParseUint(officeIdStr, 10, 64); err == nil {
				return true
			}
		}
	}

	// If the field is neither an int, uint64, nor a valid string, the validation fails
	return false
}

func CustomTrainNoGlobal(fl validator.FieldLevel) bool {
	// Attempt to get the train number as a uint64
	if trainNo, ok := fl.Field().Interface().(uint64); ok {
		// Check if the train number has exactly 5 digits
		return trainNo >= 10000 && trainNo <= 99999
	}

	// Attempt to get the train number as a string
	if trainNoStr, ok := fl.Field().Interface().(string); ok {
		// Define a regex pattern to match exactly 5 digits
		//regex := regexp.MustCompile(`^\d{5}$`)
		// Check if the string matches the regex pattern
		return trainNoPattern.MatchString(trainNoStr)
	}

	// If the value is neither a 5-digit uint64 nor a 5-digit string, validation fails
	return false
}

// seating capacity in a train
func CustomSCSGlobal(fl validator.FieldLevel) bool {
	// Get the train number from the field
	seating, ok := fl.Field().Interface().(uint64)
	if !ok {
		// If it's not a uint64, the validation fails
		return false
	}
	// Check if the strength  has exactly  1 to 4 digits
	return seating >= 1 && seating <= 9999
}
func CustomValidateGLCodePattern(fl validator.FieldLevel) bool {
	//pattern := `^GL\d{11}$`
	return ValidateWithGlobalRegex(fl, customValidateGLCodePattern)
}

// validate time stamp in format:2024-01-01T00:00:00Z
func IsValidTimestampGlobal(fl validator.FieldLevel) bool {
	// Parse the field as a time.Time
	_, err := time.Parse(time.RFC3339, fl.Field().String())
	return err != nil
}

// validate time stamp in format :DD-MM-YYYY HH:MM:SS
func TimeStampValidatePattern(f1 validator.FieldLevel) bool {
	//dateTimeRegex := regexp.MustCompile(`^(0[1-9]|[12][0-9]|3[01])-(0[1-9]|1[0-2])-(\d{4}) ([01]\d|2[0-3]):([0-5]\d):([0-5]\d)$`)
	return ValidateWithGlobalRegex(f1, timeStampValidatePattern)
}

//validate any string length to  50

func CustomValidateAnyStringLengthto50Pattern(fl validator.FieldLevel) bool {
	//pattern := `^[a-zA-Z][a-zA-Z0-9]{0,48}[a-zA-Z]$`
	// Check if the string matches the regex pattern
	return ValidateWithGlobalRegex(fl, customValidateAnyStringLengthto50Pattern)
}

// date format in yyyymmdd
func DateyyyymmddPattern(fl validator.FieldLevel) bool {
	//pattern := `^\d{4}-(0[1-9]|1[0-2])-(0[1-9]|[12]\d|3[01])$`
	// Check if the date matches the regex pattern
	return ValidateWithGlobalRegex(fl, dateyyyymmddPattern)

}
func DateddmmyyyyPattern(fl validator.FieldLevel) bool {
	//pattern := `^(0[1-9]|[12][0-9]|3[01])-(0[1-9]|1[0-2])-\d{4}$`

	// Check if the date matches the regex pattern
	return ValidateWithGlobalRegex(fl, dateddmmyyyyPattern)

}

// Custom validation function for Employee ID -- If the employee ID is 8 digit numeric value.
func ValidateEmployeeIDPattern(fl validator.FieldLevel) bool {
	//pattern := `^\d{8}$`
	return ValidateWithGlobalRegex(fl, validateEmployeeIDPattern)
}

// Cost Center ,Profit Center ,Funds Center , Customer global validaton of 10 digit integer
func GValidate10DigitIntegerGlobal(fl validator.FieldLevel) bool {

	// Handle the case where the gNumber  is a uint64
	if gNumber, ok := fl.Field().Interface().(uint64); ok {
		// Check if the phone number has exactly 10 digits
		return gNumber >= 1000000000 && gNumber <= 9999999999
	}

	// Handle the case where the gNumber  is an int
	if gNumber, ok := fl.Field().Interface().(int); ok {
		// Check if the phone number has exactly 10 digits
		return gNumber >= 1000000000 && gNumber <= 9999999999
	}
	// Check if the value is a string and attempt to parse it as an integer
	if gNumberStr, ok := fl.Field().Interface().(string); ok {
		// Convert the string to an integer
		if gNumber, err := strconv.ParseInt(gNumberStr, 10, 64); err == nil {
			return gNumber >= 1000000000 && gNumber <= 9999999999
		}
	}
	// If the field is neither a string, uint64, nor int, the validation fails
	return false
}

// ValidateGSTIN checks if the provided string is a valid GSTIN.
func ValidateGSTINPattern(fl validator.FieldLevel) bool {

	// Define the regex pattern for GSTIN validation
	//pattern := `^[0-9]{2}[A-Z]{5}[0-9]{4}[A-Z]{1}[A-Z0-9]{1}[Z]{1}[0-9]{1}$`

	return ValidateWithGlobalRegex(fl, validateGSTINPattern)
}

// ///////////////////////////////////////////////////////////////////////////////////////////
// account_no validation for 10 digit integer or 10 digit string
func ValidateAccountNoGlobal(fl validator.FieldLevel) bool {

	// Handle the case where the ValidateAccountNo  is a uint64
	if gNumber, ok := fl.Field().Interface().(uint64); ok {
		// Check if the account_no  has exactly 10 digits
		return gNumber >= 1000000000 && gNumber <= 9999999999
	}

	// Handle the case where the ValidateAccountNo  is an int
	if gNumber, ok := fl.Field().Interface().(int); ok {
		// Check if the account_no has exactly 10 digits
		return gNumber >= 1000000000 && gNumber <= 9999999999
	}
	// Check if the value is a string and attempt to parse it as an integer
	if gNumberStr, ok := fl.Field().Interface().(string); ok {
		// Convert the string to an integer
		if gNumber, err := strconv.ParseInt(gNumberStr, 10, 64); err == nil {
			return gNumber >= 1000000000 && gNumber <= 9999999999
		}
	}
	// If the field is neither a string, uint64, nor int, the validation fails
	return false
}

// ho_id validation for 7 digit integer or 7 digit string
func ValidateHOIDGlobal(fl validator.FieldLevel) bool {

	// Handle the case where the ValidateHOID  is a uint64
	if gNumber, ok := fl.Field().Interface().(uint64); ok {
		// Check if the ho_id  has exactly 7 digits
		return gNumber >= 1000000 && gNumber <= 9999999
	}

	// Handle the case where the ValidateHOID  is an int
	if gNumber, ok := fl.Field().Interface().(int); ok {
		// Check if the ho_id has exactly 7 digits
		return gNumber >= 1000000 && gNumber <= 9999999
	}
	// Check if the value is a string and attempt to parse it as an integer
	if gNumberStr, ok := fl.Field().Interface().(string); ok {
		// Convert the string to an integer
		if gNumber, err := strconv.ParseInt(gNumberStr, 10, 64); err == nil {
			return gNumber >= 1000000 && gNumber <= 9999999
		}
	}
	// If the field is neither a string, uint64, nor int, the validation fails
	return false
}

// ho_name is  a string of varchar(50) and special characters @,#/$%!^&*()<>:;"{}[] not allowed
func ValidateHONamePattern(fl validator.FieldLevel) bool {
	// Handle the case where the ho_name is a string
	if hoName, ok := fl.Field().Interface().(string); ok {
		// Check if the ho_name is not empty and has a maximum length of 50 characters
		if len(hoName) == 0 || len(hoName) > 50 {
			return false
		}

		// Define a regex pattern that disallows special characters @,#/$%!^&*()<>:;"{}[]
		// specialCharPattern := `[!@#$%^&*()<>:;"{}[\]\\]`
		// regex := regexp.MustCompile(specialCharPattern)

		// Check if the ho_name contains any special characters
		if specialCharPattern.MatchString(hoName) {
			return false
		}

		// If all checks pass, return true
		return true
	}

	// If the field is not a string, the validation fails
	return false
}

// bank_user_id validation for varchar(50)
func ValidateBankUserIDPattern(fl validator.FieldLevel) bool {
	// Handle the case where the bank_user_id is a string
	if _, ok := fl.Field().Interface().(string); ok {
		// Define a regex pattern that ensures the bank_user_id is alphanumeric and between 1 to 50 characters
		//pattern := `^[A-Z0-9]{1,50}$`

		// Check if the bank_user_id matches the pattern
		return ValidateWithGlobalRegex(fl, validateBankUserIDPattern)
	}

	// If the field is not a string, the validation fails
	return false
}

// order_number is validation for varchar(21) of type <2digit order Type><19 digit order unique number> . example: SL0240720261710456836
func ValidateOrderNumberPattern(fl validator.FieldLevel) bool {
	// Handle the case where the order_number is a string
	if _, ok := fl.Field().Interface().(string); ok {
		// Define a regex pattern that matches the format <2 uppercase letters><19 digit numeric>
		//pattern := `^[A-Z]{2}\d{19}$`
		// Check if the order_number matches the pattern
		return ValidateWithGlobalRegex(fl, validateOrderNumberPattern)
	}

	// If the field is not a string, the validation fails
	return false
}

// awbnumber is validation for varchar(13) of type <4digit Office Type><9 digit Facility ID numeric> . example: SP902269797IN
func ValidateAWBNumberPattern(fl validator.FieldLevel) bool {
	// Handle the case where the awbnumber is a string
	if _, ok := fl.Field().Interface().(string); ok {
		// Define a regex pattern that matches the format <4 uppercase letters><9 digit numeric>
		//pattern := `^[A-Z]{4}\d{9}$`

		// Check if the awbnumber matches the pattern
		return ValidateWithGlobalRegex(fl, validateAWBNumberPattern)
	}

	// If the field is not a string, the validation fails
	return false
}

// usercode is validation for integer(10) . example: 10181686
func ValidateUserCodeGlobal(fl validator.FieldLevel) bool {

	// Handle the case where the usercode is an integer
	if usercode, ok := fl.Field().Interface().(int); ok {
		// Check if the usercode has exactly 10 digits
		return usercode >= 10000000 && usercode <= 99999999
	}
	// Check if the value is a string and attempt to parse it as an integer
	if usercodeStr, ok := fl.Field().Interface().(string); ok {
		// Convert the string to an integer
		if usercode, err := strconv.ParseInt(usercodeStr, 10, 64); err == nil {
			return usercode >= 10000000 && usercode <= 99999999
		}
	}
	// If the field is neither an integer nor a string, the validation fails
	return false
}

// vas_id is validation for integer(10) . example: 1234567
func ValidateVasIDGlobal(fl validator.FieldLevel) bool {

	// Handle the case where the vas_id is an integer
	if usercode, ok := fl.Field().Interface().(int); ok {
		// Check if the vas_id has exactly 10 digits
		return usercode >= 1000000 && usercode <= 9999999
	}
	// Check if the value is a string and attempt to parse it as an integer
	if usercodeStr, ok := fl.Field().Interface().(string); ok {
		// Convert the string to an integer
		if usercode, err := strconv.ParseInt(usercodeStr, 10, 64); err == nil {
			return usercode >= 1000000 && usercode <= 9999999
		}
	}
	// If the field is neither an integer nor a string, the validation fails
	return false
}

// pnr_no is validation for varchar(32). example ABC123456
func ValidatePNRNoPattern(fl validator.FieldLevel) bool {

	// Handle the case where the pnr_no is a string
	if _, ok := fl.Field().Interface().(string); ok {
		// Define a regex pattern that matches the format
		//pattern := `^[A-Z]{3}\d{6}$`
		// Check if the pnr_no matches the pattern
		return ValidateWithGlobalRegex(fl, validatePNRNoPattern)
	}

	// If the field is not a string, the validation fails
	return false
}

// pli_id is validation for varchar(13) of type <3digit Office Type><10 digit Facility ID numeric> . example: SP902269797IN
func ValidatePLIIDPattern(fl validator.FieldLevel) bool {
	// Handle the case where the pli_id is a string
	if _, ok := fl.Field().Interface().(string); ok {
		// Define a regex pattern that matches the format <3 uppercase letters><10 digit numeric>
		//pattern := `^[A-Z]{3}\d{10}$`
		// Check if the awbnumber matches the pattern
		return ValidateWithGlobalRegex(fl, validatePLIIDPattern)
	}

	// If the field is not a string, the validation fails
	return false
}

// ValidatePaymentTransID validates the payment_trans_id using the pattern <2digit transaction Type><uuid_generate_v4()>
func ValidatePaymentTransIDPattern(fl validator.FieldLevel) bool {
	// Handle the case where the payment_trans_id is a string
	if _, ok := fl.Field().Interface().(string); ok {
		// Define a regex pattern that matches the format <2digit><uuid v4>
		//pattern := `^\d{2}[a-fA-F0-9]{8}-[a-fA-F0-9]{4}-4[a-fA-F0-9]{3}-[89abAB][a-fA-F0-9]{3}-[a-fA-F0-9]{12}$`

		// Check if the payment_trans_id matches the pattern
		return ValidateWithGlobalRegex(fl, validatePaymentTransIDPattern)
	}

	// If the field is not a string, the validation fails
	return false
}

// contract_id is validation for integer(8) . example: 40057692
func ValidateContractIDGlobal(fl validator.FieldLevel) bool {

	// Handle the case where the vas_id is an integer
	if usercode, ok := fl.Field().Interface().(int); ok {
		// Check if the vas_id has exactly 10 digits
		return usercode >= 10000000 && usercode <= 99999999
	}
	// Check if the value is a string and attempt to parse it as an integer
	if usercodeStr, ok := fl.Field().Interface().(string); ok {
		// Convert the string to an integer
		if usercode, err := strconv.ParseInt(usercodeStr, 10, 64); err == nil {
			return usercode >= 10000000 && usercode <= 99999999
		}
	}
	// If the field is neither an integer nor a string, the validation fails
	return false
}

// office_customer_id validates that the value is a valid varchar(50)
func ValidateOfficeCustomerIDPattern(fl validator.FieldLevel) bool {
	// Handle the case where the value is a string
	if _, ok := fl.Field().Interface().(string); ok {
		// Define a regex pattern to match any string with up to 50 characters

		//pattern := `^[a-zA-Z0-9\-]{1,50}$`
		// Check if the string matches the pattern
		return ValidateWithGlobalRegex(fl, validateOfficeCustomerIDPattern)
	}

	// If the field is not a string, validation fails
	return false
}

// ValidateBankID validates that the value is a valid varchar(50) with uppercase letters and digits
func ValidateBankIDPattern(fl validator.FieldLevel) bool {
	// Handle the case where the value is a string
	if _, ok := fl.Field().Interface().(string); ok {
		// Define a regex pattern to match a string with up to 50 characters consisting of uppercase letters and digits
		//pattern := `^[A-Z0-9]{1,50}$`
		// Check if the string matches the pattern
		return ValidateWithGlobalRegex(fl, validateBankIDPattern)
	}

	// If the field is not a string, validation fails
	return false
}

// region_id is validation for integer(10) . example: 9000001
func ValidateRegionIDGlobal(fl validator.FieldLevel) bool {

	// Handle the case where the region_id is an integer
	if usercode, ok := fl.Field().Interface().(int); ok {

		return usercode >= 1000000 && usercode <= 9999999
	}
	// Check if the value is a string and attempt to parse it as an integer
	if usercodeStr, ok := fl.Field().Interface().(string); ok {
		// Convert the string to an integer
		if usercode, err := strconv.ParseInt(usercodeStr, 10, 64); err == nil {
			return usercode >= 1000000 && usercode <= 9999999
		}
	}
	// If the field is neither an integer nor a string, the validation fails
	return false
}

// Contract Number is validation for integer(8) . example: 40057692
func ValidateContractNumGlobal(fl validator.FieldLevel) bool {

	// Handle the case where the ContractNum is an integer
	if usercode, ok := fl.Field().Interface().(int); ok {

		return usercode >= 10000000 && usercode <= 99999999
	}
	// Check if the value is a string and attempt to parse it as an integer
	if usercodeStr, ok := fl.Field().Interface().(string); ok {
		// Convert the string to an integer
		if usercode, err := strconv.ParseInt(usercodeStr, 10, 64); err == nil {
			return usercode >= 10000000 && usercode <= 99999999
		}
	}
	// If the field is neither an integer nor a string, the validation fails
	return false
}

// csi_facility_id is validation for varchar(13) of type <2digit Office Type><11 digit Facility ID numeric> . example BN21350000650
func ValidateCSIFacilityIDPattern(fl validator.FieldLevel) bool {
	// Handle the case where the csi_facility_id is a string
	if _, ok := fl.Field().Interface().(string); ok {
		// Define a regex pattern that matches the format <2 uppercase letters><11 digit numeric>
		//pattern := `^[A-Z]{2}\d{11}$`
		// Check if the csi_facility_id matches the pattern
		return ValidateWithGlobalRegex(fl, validateCSIFacilityIDPattern)
	}

	// If the field is not a string, the validation fails
	return false
}

// ValidatePosBookingOrderNumber validates that the value is a valid Pos booking Order Number
func ValidatePosBookingOrderNumberPattern(fl validator.FieldLevel) bool {
	// Assume the fl value is always a string

	// Define a regex pattern to match the format <2 uppercase letters><19 digits>
	//pattern := `^[A-Z]{2}\d{19}$`
	// Check if the string matches the pattern
	return ValidateWithGlobalRegex(fl, validatePosBookingOrderNumberPattern)
}

// ValidateSOLID validates that the value is a valid SOL ID
func ValidateSOLIDPattern(fl validator.FieldLevel) bool {
	// Assume the fl value is always a string

	// Define a regex pattern to match the format <6 digits pincode><2 digits office type number>
	//pattern := `^\d{6}\d{2}$`
	// Check if the string matches the pattern
	return ValidateWithGlobalRegex(fl, validateSOLIDPattern)
}

// CIF Number is validation for integer . example: 327711299
func ValidateCIFNumGlobal(fl validator.FieldLevel) bool {

	// Handle the case where the CIF is an integer
	if usercode, ok := fl.Field().Interface().(int); ok {

		return usercode >= 100000000 && usercode <= 999999999
	}
	// Check if the value is a string and attempt to parse it as an integer
	if usercodeStr, ok := fl.Field().Interface().(string); ok {
		// Convert the string to an integer
		if usercode, err := strconv.ParseInt(usercodeStr, 10, 64); err == nil {
			return usercode >= 100000000 && usercode <= 999999999
		}
	}
	// If the field is neither an integer nor a string, the validation fails
	return false
}

// ValidatePLIOfficeID validates that the value is a valid PLI Office ID
func ValidatePLIOfficeIDPattern(fl validator.FieldLevel) bool {
	// Assume the fl value is always a string

	// Define a regex pattern to match the format <3 uppercase letters><10 digits>
	//pattern := `^[A-Z]{3}\d{10}$`
	// Check if the string matches the pattern
	return ValidateWithGlobalRegex(fl, validatePLIOfficeIDPattern)
}

// ValidateProductCode validates that the value is a valid product code
func ValidateProductCodePattern(fl validator.FieldLevel) bool {
	// Assume the fl value is always a string

	// Define a regex pattern to match the format <3 uppercase letters><12 digits>
	//pattern := `^[A-Z]{3}\d{12}$`

	// Check if the string matches the pattern
	return ValidateWithGlobalRegex(fl, validateProductCodePattern)
}

// ValidateCustomerID validates that the value is a valid 10-digit customer ID
func ValidateCustomerIDPattern(fl validator.FieldLevel) bool {
	// Handle the case where the value is a string
	if _, ok := fl.Field().Interface().(string); ok {
		// Define a regex pattern to match a 10-digit number
		//pattern := `^\d{10}$`
		// Check if the string matches the pattern
		return ValidateWithGlobalRegex(fl, validateCustomerIDPattern)
	}

	// Handle the case where the value is an integer
	if customerIDInt, ok := fl.Field().Interface().(int); ok {
		// Convert the integer to a string
		customerIDStr := strconv.Itoa(customerIDInt)

		// Check if the integer has exactly 10 digits
		return len(customerIDStr) == 10
	}

	// If the field is neither a string nor an integer, validation fails
	return false
}

// ValidateFacilityID validates that the value is a valid facility ID
func ValidateFacilityIDPattern(fl validator.FieldLevel) bool {

	// Define a regex pattern to match the format <2 uppercase letters><11 digits>
	//pattern := `^[A-Z]{2}\d{11}$`
	// Check if the string matches the pattern
	return ValidateWithGlobalRegex(fl, validateFacilityIDPattern)
}

// tariff_id  is validation for integer . example: 1234567890 10 digit
func ValidateTariffIDGlobal(fl validator.FieldLevel) bool {

	// Handle the case where the tariff_id is an integer
	if usercode, ok := fl.Field().Interface().(int); ok {

		return usercode >= 1000000000 && usercode <= 9999999999
	}
	// Check if the value is a string and attempt to parse it as an integer
	if usercodeStr, ok := fl.Field().Interface().(string); ok {
		// Convert the string to an integer
		if usercode, err := strconv.ParseInt(usercodeStr, 10, 64); err == nil {
			return usercode >= 1000000000 && usercode <= 9999999999
		}
	}
	// If the field is neither an integer nor a string, the validation fails
	return false
}

// ValidateApplicationID validates that the value is a valid application ID
func ValidateApplicationIDPattern(fl validator.FieldLevel) bool {
	// Define a regex pattern to match the format <3 uppercase letters><12 digits with hyphen>
	//pattern := `^[A-Z]{3}\d{8}-\d{3}$`
	// Check if the string matches the pattern
	return ValidateWithGlobalRegex(fl, validateApplicationIDPattern)
}

// ValidateReceiverKYCReference validates that the value is a valid receiver KYC reference
func ValidateReceiverKYCReferencePattern(fl validator.FieldLevel) bool {

	// Define a regex pattern to match the format KYCREF followed by up to 44 alphanumeric characters
	//pattern := `^KYCREF[A-Z0-9]{0,44}$`
	// Check if the string matches the pattern
	return ValidateWithGlobalRegex(fl, validateReceiverKYCReferencePattern)
}

// Circle_id is validation for integer . example: 90000013 starting with 7 digit
func ValidateCircleIDGlobal(fl validator.FieldLevel) bool {

	// Handle the case where the Circle_id is an integer
	if usercode, ok := fl.Field().Interface().(int); ok {

		return usercode >= 9000001 && usercode <= 9999999999
	}
	// Check if the value is a string and attempt to parse it as an integer
	if usercodeStr, ok := fl.Field().Interface().(string); ok {
		// Convert the string to an integer
		if usercode, err := strconv.ParseInt(usercodeStr, 10, 64); err == nil {
			return usercode >= 9000001 && usercode <= 9999999999
		}
	}
	// If the field is neither an integer nor a string, the validation fails
	return false
}

// office_customer validates that the value is a valid varchar(50)
func ValidateOfficeCustomerPattern(fl validator.FieldLevel) bool {
	// Regular expression to allow only alphanumeric characters and spaces
	// This will disallow special characters like @, #, $, %, etc.
	//pattern := `^[a-zA-Z0-9\s]+$`

	// Get the field value and convert it to a string
	officeCustomer, ok := fl.Field().Interface().(string)
	if !ok {
		return false
	}

	// Check if the length of the string is within 50 characters
	if len(officeCustomer) > 50 {
		return false
	}

	// Check if the office_customer string matches the allowed pattern
	return ValidateWithGlobalRegex(fl, validateOfficeCustomerPattern)
}

// ValidatePRAN validates that the value is a valid 12-digit PRAN number, either as a string or integer
func ValidatePRANPattern(fl validator.FieldLevel) bool {
	// Handle the case where the PRAN is a string
	if _, ok := fl.Field().Interface().(string); ok {
		// Define a regex pattern to match exactly 12 digits
		//pattern := `^\d{12}$`

		return ValidateWithGlobalRegex(fl, validatePRANPattern)
	}

	// Handle the case where the PRAN is an int64
	if pranInt, ok := fl.Field().Interface().(int64); ok {
		// Check if the int64 falls within the 12-digit range
		return pranInt >= 100000000000 && pranInt <= 999999999999
	}

	// If the field is neither a valid string nor a valid integer, the validation fails
	return false
}
