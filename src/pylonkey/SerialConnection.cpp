/*
 * File:   TimeoutSerial.cpp
 * Author: Terraneo Federico
 * Distributed under the Boost Software License, Version 1.0.
 * Created on September 12, 2009, 3:47 PM
 *
 * v1.05: Fixed a bug regarding reading after a timeout (again).
 *
 * v1.04: Fixed bug with timeout set to zero
 *
 * v1.03: Fix for Mac OS X, now fully working on Mac.
 *
 * v1.02: Code cleanup, speed improvements, bug fixes.
 *
 * v1.01: Fixed a bug that caused errors while reading after a timeout.
 *
 * v1.00: First release.
 */

#include "SerialConnection.h"

#include <string>
#include <algorithm>
#include <iostream>
#include <boost/bind.hpp>
#include <boost/algorithm/string/predicate.hpp> // for startswith() and endswith()

#include "sync.h"

using namespace std;
using namespace boost;

SerialConnection::SerialConnection(): io(), port(io), timer(io),
        timeout(posix_time::seconds(0)), result(resultInProgress), bytesTransferred(0) {}

SerialConnection::SerialConnection(const std::string& devname, unsigned int baud_rate,
        asio::serial_port_base::parity opt_parity,
        asio::serial_port_base::character_size opt_csize,
        asio::serial_port_base::flow_control opt_flow,
        asio::serial_port_base::stop_bits opt_stop)
        : io(), port(io), timer(io), timeout(posix_time::seconds(0))
{
    open(devname,baud_rate,opt_parity,opt_csize,opt_flow,opt_stop);
}

void SerialConnection::open(const std::string& devname, unsigned int baud_rate,
        asio::serial_port_base::parity opt_parity,
        asio::serial_port_base::character_size opt_csize,
        asio::serial_port_base::flow_control opt_flow,
        asio::serial_port_base::stop_bits opt_stop)
{
    if(isOpen()) close();
    port.open(devname);
    port.set_option(asio::serial_port_base::baud_rate(baud_rate));
    port.set_option(opt_parity);
    port.set_option(opt_csize);
    port.set_option(opt_flow);
    port.set_option(opt_stop);
}

bool SerialConnection::isOpen() const
{
    return port.is_open();
}

void SerialConnection::close()
{
    if(isOpen()==false) return;
    port.close();
}

void SerialConnection::setTimeout(const posix_time::time_duration& t)
{
    timeout=t;
}

void SerialConnection::write(const char *data, size_t size)
{
    asio::write(port,asio::buffer(data,size));
}

void SerialConnection::write(const std::vector<char>& data)
{
    asio::write(port,asio::buffer(&data[0],data.size()));
}

void SerialConnection::writeString(const std::string& s)
{
    asio::write(port,asio::buffer(s.c_str(),s.size()));
}

void SerialConnection::read(char *data, size_t size)
{
    if(readData.size()>0)//If there is some data from a previous read
    {
        istream is(&readData);
        size_t toRead=min(readData.size(),size);//How many bytes to read?
        is.read(data,toRead);
        data+=toRead;
        size-=toRead;
        if(size==0) return;//If read data was enough, just return
    }
    
    setupParameters=ReadSetupParameters(data,size);
    performReadSetup(setupParameters);

    //For this code to work, there should always be a timeout, so the
    //request for no timeout is translated into a very long timeout
    if(timeout!=posix_time::seconds(0)) timer.expires_from_now(timeout);
    else timer.expires_from_now(posix_time::hours(100000));
    
    timer.async_wait(boost::bind(&SerialConnection::timeoutExpired,this,
                asio::placeholders::error));
    
    result=resultInProgress;
    bytesTransferred=0;
    for(;;)
    {
        io.run_one();
        switch(result)
        {
            case resultSuccess:
                timer.cancel();
                return;
            case resultTimeoutExpired:
                port.cancel();
                throw(timeout_exception("Timeout expired"));
            case resultError:
                timer.cancel();
                port.cancel();
                throw(boost::system::system_error(boost::system::error_code(),
                        "Error while reading"));
            default:
                break;
                //if resultInProgress remain in the loop
        }
    }
}

std::vector<char> SerialConnection::read(size_t size)
{
    vector<char> result(size,'\0');//Allocate a vector with the desired size
    read(&result[0],size);//Fill it with values
    return result;
}

std::string SerialConnection::readString(size_t size)
{
    string result(size,'\0');//Allocate a string with the desired size
    read(&result[0],size);//Fill it with values
    return result;
}

std::string SerialConnection::readStringUntil(const std::string& delim)
{
    // Note: if readData contains some previously read data, the call to
    // async_read_until (which is done in performReadSetup) correctly handles
    // it. If the data is enough it will also immediately call readCompleted()
    setupParameters=ReadSetupParameters(delim);
    performReadSetup(setupParameters);

    //For this code to work, there should always be a timeout, so the
    //request for no timeout is translated into a very long timeout
    if(timeout!=posix_time::seconds(0)) timer.expires_from_now(timeout);
    else timer.expires_from_now(posix_time::hours(100000));

    timer.async_wait(boost::bind(&SerialConnection::timeoutExpired,this,
                asio::placeholders::error));

    result=resultInProgress;
    bytesTransferred=0;
    for(;;)
    {
        io.run_one();
        switch(result)
        {
            case resultSuccess:
                {
                    timer.cancel();
                    bytesTransferred-=delim.size();//Don't count delim
                    istream is(&readData);
                    string result(bytesTransferred,'\0');//Alloc string
                    is.read(&result[0],bytesTransferred);//Fill values
                    is.ignore(delim.size());//Remove delimiter from stream
                    return result;
                }
            case resultTimeoutExpired:
                port.cancel();
                throw(timeout_exception("Timeout expired"));
            case resultError:
                timer.cancel();
                port.cancel();
                throw(boost::system::system_error(boost::system::error_code(),
                        "Error while reading"));
            default:
                break;
                //if resultInProgress remain in the loop
        }
    }

    // never reached
    return NULL;
}

void SerialConnection::performReadSetup(const ReadSetupParameters& param)
{
    if(param.fixedSize)
    {
        asio::async_read(port,asio::buffer(param.data,param.size),boost::bind(
                &SerialConnection::readCompleted,this,asio::placeholders::error,
                asio::placeholders::bytes_transferred));
    } else {
        asio::async_read_until(port,readData,param.delim,boost::bind(
                &SerialConnection::readCompleted,this,asio::placeholders::error,
                asio::placeholders::bytes_transferred));
    }
}

void SerialConnection::timeoutExpired(const boost::system::error_code& error)
{
     if(!error && result==resultInProgress) result=resultTimeoutExpired;
}

void SerialConnection::readCompleted(const boost::system::error_code& error,
        const size_t bytesTransferred)
{
    if(!error)
    {
        result=resultSuccess;
        this->bytesTransferred=bytesTransferred;
        return;
    }

    //In case a asynchronous operation is cancelled due to a timeout,
    //each OS seems to have its way to react.
    #ifdef _WIN32
    if(error.value()==995) return; //Windows spits out error 995
    #elif defined(__APPLE__)
    if(error.value()==45)
    {
        //Bug on OS X, it might be necessary to repeat the setup
        //http://osdir.com/ml/lib.boost.asio.user/2008-08/msg00004.html
        performReadSetup(setupParameters);
        return;
    }
    #else //Linux
    if(error.value()==125) return; //Linux outputs error 125
    #endif

    result=resultError;
}

bool SerialConnection::sendAndReceive(const std::string line, vector<string> &vLines)
{
    LOCK(cs_connection);
    writeString(line + "\r");

    string s = readStringUntil("\r\n");

    vLines.push_back(s);
    while (1) {
        if (s == "OK")
            return true;

        if (boost::algorithm::starts_with(s, "ERROR"))
            return false;

        s = readStringUntil("\r\n");
        vLines.push_back(s);
    }

    return false; // never reached
}

bool SerialConnection::sendCommand(const std::string command) {
    LOCK(cs_connection);
    writeString(command + "\r");
    string s = readStringUntil("\r\n");
    while (s != "OK" && !boost::algorithm::starts_with(s, "ERROR")) {
        s = readStringUntil("\r\n");
    }

    return s == "OK";
}
