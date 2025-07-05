# Excel XLOOKUP Tool

A Python script that performs XLOOKUP-like functionality in Excel files with an interactive command-line interface.

## Features

- 🔍 **Interactive XLOOKUP**: Perform lookups across Excel sheets
- 📊 **Visual Data Preview**: See sample data from your sheets
- 🎯 **Flexible Column Selection**: Choose any column for lookup and return values
- 🔄 **Multiple Sheet Support**: Lookup across different sheets in the same workbook
- 💬 **User-Friendly Interface**: Step-by-step guided process

## Installation

1. **Install Python Dependencies**:
   ```bash
   pip install -r requirements.txt
   ```

2. **Or install manually**:
   ```bash
   pip install openpyxl pandas
   ```

## Usage

1. **Run the script**:
   ```bash
   python xlookup_tool.py
   ```

2. **Follow the interactive prompts**:
   - Enter the path to your Excel file
   - Select the lookup sheet
   - Choose the lookup column
   - Select the return sheet (can be same as lookup sheet)
   - Choose the return column
   - Enter lookup values interactively

## Example Workflow

```
🔍 Excel XLOOKUP Tool
==================================================

📁 Step 1: Load Excel File
Enter the path to your Excel file: data.xlsx
✅ Successfully loaded: data.xlsx

📋 Step 2: Select Lookup Sheet
Available sheets:
  1. Sales
  2. Products
  3. Customers

Enter the sheet name or number for lookup data: 1

📊 Sample data from 'Sales' (first 5 rows):
--------------------------------------------------------------------------------
ProductID     | CustomerID    | Quantity      | Price         | Date          
--------------------------------------------------------------------------------
1001          | C001          | 5             | 29.99         | 2024-01-15    
1002          | C002          | 3             | 19.99         | 2024-01-16    
1003          | C001          | 2             | 49.99         | 2024-01-17    

🔍 Step 3: Select Lookup Column
Available columns in 'Sales':
  1. ProductID
  2. CustomerID
  3. Quantity
  4. Price
  5. Date

Enter the column number containing lookup values: 1

📊 Step 4: Select Return Sheet
Available sheets:
  1. Sales
  2. Products
  3. Customers

Enter the sheet name or number for return data: 2

📈 Step 5: Select Return Column
Available columns in 'Products':
  1. ProductID
  2. ProductName
  3. Category
  4. Supplier

Enter the column number containing return values: 2

🔎 Step 6: Perform Lookups
==================================================
Enter lookup values (type 'quit' to exit):

Enter lookup value: 1001
✅ Found: Laptop Pro

Enter lookup value: 1002
✅ Found: Wireless Mouse

Enter lookup value: 9999
❌ No match found for: 9999

Enter lookup value: quit

👋 Thank you for using Excel XLOOKUP Tool!
```

## How It Works

The script performs the following steps:

1. **Load Excel File**: Opens your Excel workbook using openpyxl
2. **Sheet Selection**: Shows available sheets and lets you choose
3. **Data Preview**: Displays sample data to help you understand the structure
4. **Column Selection**: Lists available columns with headers
5. **Interactive Lookup**: Enter lookup values and get results immediately

## Supported Excel Formats

- `.xlsx` files (Excel 2007 and later)
- `.xlsm` files (Excel with macros)
- `.xltx` files (Excel templates)

## Error Handling

The script includes comprehensive error handling for:
- Invalid file paths
- Missing sheets
- Invalid column selections
- Data type mismatches
- File corruption issues

## Tips for Best Results

1. **Clean Data**: Ensure your Excel file has consistent data types in lookup columns
2. **Headers**: The first row should contain column headers
3. **No Empty Rows**: Remove any completely empty rows for better performance
4. **Data Types**: Be consistent with data types (e.g., all ProductIDs as numbers or all as text)

## Troubleshooting

**"File not found" error**:
- Check the file path is correct
- Ensure the file exists in the specified location
- Use absolute paths if needed

**"No sheets found" error**:
- Verify the Excel file is not corrupted
- Check if the file actually contains worksheets

**"Column not found" error**:
- Make sure you're entering a valid column number
- Check that the column exists in the selected sheet

## License

This tool is provided as-is for educational and personal use. 