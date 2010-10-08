#!/usr/bin/python
# -*- coding: utf-8 -*-

""" This file is part of B{Domogik} project (U{http://www.domogik.org}).

License
=======

B{Domogik} is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

B{Domogik} is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with Domogik. If not, see U{http://www.gnu.org/licenses}.

Plugin purpose
=============

- Json Helper for REST

Implements
==========

JSonHelper object



@author: Friz <fritz.smh@gmail.com>
@copyright: (C) 2007-2009 Domogik project
@license: GPL(v3)
@organization: Domogik
"""
import re
import json


class JSonHelper():
    """ Easy way to create a json or jsonp structure
    """

    def __init__(self, status = "OK", code = 0, description = ""):
        """ Init json structure
            @param status : OK/ERROR
            @param code : 0...999 : error code. If error no referenced, 999
            @param description : error description
        """
        if status == "OK":
            self.set_ok()
        else:
            self.set_error(code, description)
        self._data_type = ""
        self._data_values = ""
        self._nb_data_values = 0
        #self._jsonp = ""
        #self._jsonp_cb = ""
        #self._status = ""

    def set_jsonp(self, jsonp, jsonp_cb):
        """ define jsonp mode
            @param jsonp : True/False : True : jsonp mode
            @param jsonp_cb : name of jsonp callback
        """
        self._jsonp = jsonp
        self._jsonp_cb = jsonp_cb

    def set_ok(self, code=0, description=None):
        """ set ok status
        """
        self._status = '"status" : "OK", "code" : ' + str(code) + ', "description" : "' + str(description) + '",'

    def set_error(self, code=0, description=None):
        """ set error status
            @param code : error code
            @param description : error description
        """
        description = description.replace('\n', "\\n")
        self._status = '"status" : "ERROR", "code" : ' + str(code) + ', "description" : "' + str(description) + '",'

    def set_data_type(self, data_type):
        """ set data type
            @param data_type : data type
        """
        self._data_type = data_type

    def add_data(self, data):
        """ add data to json structure in 'type' table
            @param data : data to add
        """
        data_out = ""
        self._nb_data_values += 1

        # issue to force data not to be in cache
        # TODO : update when all tables will be defined!!!
        table_list = ["device_feature",  \
                     "area",  \
                     "device",  \
                     "device_usage",  \
                     "device_config",  \
                     "device_feature_association",  \
                     "device_stats",  \
                     "device_stats_value",  \
                     "device_technology",  \
                     "plugin_config",  \
                     "plugin_config_param",  \
                     "device_type",  \
                     "device_feature_model",  \
                     "uiitemconfig",  \
                     "room",  \
                     "useraccount",  \
                     "sensor_reference_data",  \
                     "person",  \
                     "system_config",  \
                     "system_stats",  \
                     "system_statsvalue", \
                     "id", \
                     "device_id", \
                     "name"]

        for table in table_list:
            if hasattr(data, table):
                pass
      
        if data == None:
            return

        data_out += self._process_data(data)
        data_out = data_out.replace('\n', "\\n")
        self._data_values += data_out
            




    def _process_data(self, data, idx = 0, key = None):
        """ Recursive function. Generate json data
        """
        #print "==== PROCESS DATA " + str(idx) + " ===="

        # check deepth in recursivity
        if idx > 4:
            return "#MAX_DEPTH# "

        # define data types
        db_type = ("DeviceFeature", "Area", "Device", "DeviceUsage", \
                   "DeviceConfig", "DeviceStats", "DeviceStatsValue", \
                   "DeviceTechnology", "PluginConfig", "PluginConfigParam",  \
                   "DeviceType", "UIItemConfig", "Room", "UserAccount", \
                   "SensorReferenceData", "Person", "SystemConfig", \
                   "SystemStats", "SystemStatsValue", "Trigger", \
                   "DeviceFeatureAssociation", "DeviceFeatureModel") 
        instance_type = ("instance")
        num_type = ("int", "float", "long")
        str_type = ("str", "unicode", "bool", "datetime", "date")
        none_type = ("NoneType")
        tuple_type = ("tuple", "NamedTuple")
        list_type = ("list")
        dict_type = ("dict")

        data_json = ""

        # get data type
        data_type = type(data).__name__
        #print "TYPE=%s" % data_type
        #print data

        ### type instance (sql object)
        if data_type in instance_type:
            # get <object>._type value
            try:
                sub_data_type = data._type.lower()
            except:
                sub_data_type = "instance"
            #print "SUB TYPE = %s" % sub_data_type

            if idx == 0:
                data_json += "{"
            else:
                data_json += '"%s" : {' % sub_data_type

            for key in data.__dict__:
                sub_data_key = key
                sub_data = data.__dict__[key]
                sub_data_type = type(sub_data).__name__
                #print "    DATA KEY : " + str(sub_data_key)
                #print "    DATA : " + str(sub_data)
                #print "    DATA TYPE : " + str(sub_data_type)
                data_json += self._process_sub_data(idx + 1, False, sub_data_key, sub_data, sub_data_type, db_type, instance_type, num_type, str_type, none_type, tuple_type, list_type, dict_type)
            data_json = data_json[0:len(data_json)-1] + "},"

        ### type : SQL table
        elif data_type in db_type: 
            data_json += "{" 
            for key in data.__dict__: 
                sub_data_key = key 
                sub_data = data.__dict__[key] 
                sub_data_type = type(sub_data).__name__ 
                #print "    DATA KEY : " + str(sub_data_key) 
                #print "    DATA : " + unicode(sub_data) 
                #print "    DATA TYPE : " + str(sub_data_type) 
                my_buffer = self._process_sub_data(idx + 1, False, sub_data_key, sub_data, sub_data_type, db_type, instance_type, num_type, str_type, none_type, tuple_type, list_type, dict_type) 
                # if max depth in recursivity, we don't display "foo : {}"
                if re.match(".*#MAX_DEPTH#.*", my_buffer) is None:
                    data_json += my_buffer
            data_json = data_json[0:len(data_json)-1] + "}," 

        ### type : list
        elif data_type in list_type:
            # get first data type
            if len(data) > 0:
                sub_data_elt0_type = type(data[0]).__name__
                #print "DATA=%s" % data
            else:
                #print "DATA vide=%s" % data
                data_json = '"%s" : [],' % key
                return data_json
            # start table
            if sub_data_elt0_type in ("dict", "str", "int", "tuple", "NamedTuple"):
                data_json += '"%s" : [' % key
            else:
                display_sub_data_elt0_type = re.sub(r"([^^])([A-Z][a-z])",
                             r"\1_\2",
                             sub_data_elt0_type).lower()
                data_json += '"%s" : [' % display_sub_data_elt0_type

            # process each data
            for sub_data in data:
                sub_data_key  = "NOKEY"
                sub_data_type = type(sub_data).__name__
                #print "    DATA KEY : " + str(sub_data_key)
                #print "    DATA : " + str(sub_data)
                #print "    DATA TYPE : " + str(sub_data_type)
                data_json += self._process_sub_data(idx + 1, True, sub_data_key, sub_data, sub_data_type, db_type, instance_type, num_type, str_type, none_type, tuple_type, list_type, dict_type)
            # finish table
            data_json = data_json[0:len(data_json)-1] + "],"


        ### type : dict
        elif data_type in dict_type:
            if key != None and key != "NOKEY":
                data_json += '"%s" : {' % key
            else:
                data_json += "{"
            for key in data:
                sub_data_key = key
                sub_data = data[key]
                sub_data_type = type(sub_data).__name__
                #print "    DATA KEY : " + str(sub_data_key)
                #print "    DATA : " + str(sub_data)
                #print "    DATA TYPE : " + str(sub_data_type)
                data_json += self._process_sub_data(idx + 1, False, sub_data_key, sub_data, sub_data_type, db_type, instance_type, num_type, str_type, none_type, tuple_type, list_type, dict_type)
            if data == {}:
                data_json += "},"
            else:
                data_json = data_json[0:len(data_json)-1] + "},"

        ### type : str
        elif data_type in str_type:
            data_json += '"%s",' % data

        return data_json



    def _process_sub_data(self, idx, is_table, sub_data_key, sub_data, sub_data_type, db_type, instance_type, num_type, str_type, none_type, tuple_type, list_type, dict_type):
        """ process sub data : generate output or call appropriate function
        """
        if (idx != 0 and sub_data_key == "device_stats"):
            return "#MAX_DEPTH# "
        if sub_data_key[0] == "_":
            return ""
        data_tmp = ""
        if sub_data_type in db_type: 
            if is_table is False:  # and idx != 0: 
                display_sub_data_type = re.sub(r"([^^])([A-Z][a-z])",
                             r"\1_\2",
                             sub_data_type).lower()
                if display_sub_data_type != "NOKEY":
                    data_tmp = '"%s" : ' % display_sub_data_type
            data_tmp += self._process_data(sub_data, idx)
        elif sub_data_type in instance_type:
            data_tmp += self._process_data(sub_data, idx)
        elif sub_data_type in list_type:
            data_tmp += self._process_data(sub_data, idx, sub_data_key)
        elif sub_data_type in dict_type:
            data_tmp += self._process_data(sub_data, idx, sub_data_key)
        elif sub_data_type in tuple_type:
            data_tmp += '%s,' % json.dumps(sub_data)
        elif sub_data_type in num_type:
            if sub_data_key == "NOKEY":
                data_tmp = '%s,' % sub_data
            else:
                data_tmp = '"%s" : %s,' % (sub_data_key, sub_data)
        elif sub_data_type in str_type:
            if sub_data_key == "NOKEY":
                data_tmp = '"%s",' % sub_data
            else:
                data_tmp = '"%s" : "%s",' % (sub_data_key, sub_data)
        elif sub_data_type in none_type:
            if sub_data_key == "NOKEY":
                data_tmp = '"",'
            else:
                data_tmp = '"%s" : "",' % (sub_data_key)
        else: 
            data_tmp = ""
        
        return data_tmp




        

    def get(self):
        """ getter for all json data created
            @return json or jsonp data
        """
        if self._jsonp is True and self._jsonp_cb != "":
            json_buf = "%s (" % self._jsonp_cb
        else:
            json_buf = ""

        if self._data_type != "":
            json_buf += '{%s "%s" : [%s]}' % (self._status,   self._data_type, self._data_values[0:len(self._data_values)-1])
        else:
            json_buf += '{%s}' % self._status[0:len(self._status)-1]

        if self._jsonp is True and self._jsonp_cb != "":
            json_buf += ")"
        return json_buf
        
    

