from datetime import datetime
import ipaddress

def unix_to_standard_time(unix_timestamp:str):
    """
  This function cunvert UnixTime to standart time formate.
  Args:
      unix_timestamp: Time in unix formate.
  Returns:
      Time in YYYYMMDD HHMMSS formate.
  """
    return datetime.fromtimestamp(unix_timestamp).strftime('%Y-%m-%d %H:%M:%S')

def isValidPortNumber(port:str):
    
    port = str(port)
    if port.isnumeric() and int(port)>=0 and int(port)<=65353:
            return True
    else:
        return False
    

def get_data_size(data:str):
  """
  This function calculates the size of a given data in bytes.

  Args:
      data: The data to be measured, can be a string of bytes or a bytes object.

  Returns:
      The size of the data in bytes as an integer.
  """
  if isinstance(data, str):
    # Handle string input (assuming UTF-8 encoding)
    return len(data.encode('utf-8'))
  else:
    # Handle bytes object directly
    return len(data)

def isValidIPv4(IP:str):
    try:
        ipaddress.IPv4Address(IP)
        return True
    except Exception as e :
        return False    

def main():
    print("HelloWorld")

    ip_test_add = "127.0.0.0qq"
    print(isValidIPv4(ip_test_add))

if __name__ == "__main__":
    main()

    
