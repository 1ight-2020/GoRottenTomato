package netWork

import (
	"GoRottenTomato/krb5/KRBError"
	"GoRottenTomato/krb5/flags"
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"time"
)

// https://tools.ietf.org/html/rfc4120#section-7.2.2
func SendToKDC(dcIP string, data []byte) ([]byte, error) {
	resp, err := sendKDC(dcIP, data)
	if err != nil {
		if e, ok := err.(KRBError.KRB_Error); ok {
			return resp, e
		}
		return resp, fmt.Errorf("communication error with KDC via TCP: %v", err)
	}
	return resp, nil
}

func sendKDC(dcIP string, data []byte) ([]byte, error) {
	con, err := dialKDC(dcIP)
	if err != nil {
		return nil, err
	}

	resp, err := send(con, data)
	if err != nil {
		return nil, err
	}

	return checkKRBError(resp)
}

func dialKDC(dcIP string) (*net.TCPConn, error) {
	con, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d",judge(dcIP), flags.KDC_PORT), 10*time.Second)
	if err != nil {
		return nil, fmt.Errorf("connect to KDC failed %v", err)
	}else {
		if err := con.SetDeadline(time.Now().Add(10*time.Second)); err != nil {
			return nil, fmt.Errorf("connect to KDC failed %v", err)
		}
		return con.(*net.TCPConn), nil
	}
}

func send(con *net.TCPConn, data []byte) ([]byte, error) {
	defer con.Close()
	var buf bytes.Buffer

	err := binary.Write(&buf, binary.BigEndian, uint32(len(data)))
	if err != nil {
		return nil, err
	}
	data = append(buf.Bytes(), data...)

	_, err = con.Write(data)
	if err != nil {
		return nil, fmt.Errorf("sending to KDC(%s) failed %v", con.RemoteAddr().String(), err)
	}

	resp := make([]byte, 4, 4)
	_, err = con.Read(resp)
	if err != nil {
		return nil, fmt.Errorf("read KDC(%s) response failed %v", con.RemoteAddr().String(), err)
	}
	size := binary.BigEndian.Uint32(resp)
	respData := make([]byte, size, size)
	_, err = io.ReadFull(con, respData)
	if err != nil {
		return nil, fmt.Errorf("can not read KDC(%s) response size %d %v", con.RemoteAddr().String(),size ,err)
	}

	if len(respData) < 1 {
		return nil, fmt.Errorf("read KDC(%s) response failed KRB_AP_ERR_BAD_INTEGRITY", con.RemoteAddr().String())
	}

	return respData, nil
}

func checkKRBError(data []byte) ([]byte, error) {
	var krberr KRBError.KRB_Error
	if err := krberr.Unmarshal(data); err == nil {
		return data, krberr
	}
	return data, nil
}

func judge(dcip string) string {
	for i := 0; i < len(dcip); i++ {
		switch dcip[i] {
		case '.':
			return dcip
		case ':':
			return fmt.Sprintf("[%s]", dcip)
		}
	}
	return dcip
}