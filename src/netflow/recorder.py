import json
import os
import time

class Recorder:
    """
    This class is used to persist data. Currently
    it dumps data to file
    """

    @classmethod
    def set_output_file(cls, output_file):
        """
        Sets path of save file
        """
        cls.output_file = output_file

    @classmethod
    def save(cls, data):
        """
        Dump data to file
        """
        if not os.path.exists(cls.output_file):
            with open(cls.output_file, 'w') as fh:
                fh.write(json.dumps({}))

        with open(cls.output_file, 'r') as fh:
            existing_data = json.loads(fh.read())

        existing_data[time.time()] = data

        with open(cls.output_file, 'w') as fh:
            fh.write(json.dumps(existing_data))
