""" THIS IS A PYTHON FILE MEANT FOR DEBUGGING THE FLASK APP. 
REMOVE ME AFTER IM DONE!"""

import logging
import logging.handlers
from pathlib import Path
from os import mkdir

logging_folder = Path(__file__).parent / "logs"

def create_dir() -> bool:
    """Creates the logs folder, returns false if not created,
    else true"""
    global logging_folder 

    try:
        mkdir(logging_folder)
    except FileExistsError:
        pass
    except PermissionError:
        raise PermissionError("ERR! Permission denied to create logs")
    except Exception as e:
        raise e
    
    return True
    
def setup_custom_logger() -> logging.Logger:
    """Sets up logger for info handling nad debugging"""
    global logging_folder
    
    if not logging_folder.exists():
        create_dir()
        
    custom_logger = logging.Logger("custom")
    custom_logger.setLevel(logging.DEBUG)


    # Logging to a file
    file_handler = logging.handlers.RotatingFileHandler(
        filename=logging_folder/"custom.log",
        maxBytes=5*(1024**5),
        backupCount=3
    )
    file_handler.setFormatter(
        logging.Formatter("%(asctime)s - %(name)s - %(levelname)s - %(message)s")
    )

    custom_logger.addHandler(file_handler)

    return custom_logger

if __name__ == "__main__":
    my_logger = setup_custom_logger()
    my_logger.info("TESTING")
    my_logger.debug("TESTING")