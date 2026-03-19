package kepresolv

import (
    "bytes"
    "encoding/binary"
	"errors"
	"io"
)

func bytesToInt64(b []byte) int64 {
    if len(b) != 5 {
        panic("invalid length")
    }
    var t uint64
    t |= uint64(b[0]) << 32
    t |= uint64(b[1]) << 24
    t |= uint64(b[2]) << 16
    t |= uint64(b[3]) << 8
    t |= uint64(b[4])
    return int64(t)
}

func Resolv(data []byte) ([]byte, []byte, int64, []byte,byte,uint64,[]byte,uint16,[]byte, error) {
    //txt数据，用户名,timestamp,point_to,Typeid,hash,tag,point_to_root(主贴)
	r := bytes.NewReader(data)

    const (
        maxDomainLen = 250
        maxPointLen  = 160
        maxTextLen   = 65535
    )

    // version
    version, err := r.ReadByte()
    if err != nil {
        return nil, nil, 0, nil, 0, 0, nil, 0, nil, err
    }
    if version != 1 {
        return nil, nil, 0, nil, 0, 0, nil, 0, nil, errors.New("unsupported version")
    }

    // hashType
    _, err = r.ReadByte()
    if err != nil {
        return nil, nil, 0, nil, 0, 0, nil, 0, nil, err
    }

    // domainLen
    domainLen, err := r.ReadByte()
    if err != nil {
        return nil, nil, 0, nil, 0, 0, nil, 0, nil, err
    }
    if domainLen == 0 || domainLen > maxDomainLen {
        return nil, nil, 0, nil, 0, 0, nil, 0, nil, errors.New("invalid domain length")
    }

    // timestamp
    timestampBytes := make([]byte, 5)
    if _, err := io.ReadFull(r, timestampBytes); err != nil {
        return nil, nil, 0, nil, 0, 0, nil, 0, nil, err
    }
    timestamp := bytesToInt64(timestampBytes)

    // length
    lg := make([]byte, 2)
    if _, err := io.ReadFull(r, lg); err != nil {
        return nil, nil, 0, nil, 0, 0, nil, 0, nil, err
    }
    length := binary.BigEndian.Uint16(lg)
    if length > maxTextLen {
        return nil, nil, 0, nil, 0, 0, nil, 0, nil, errors.New("text too large")
    }

    // keys
	mainkey := make([]byte, 32)
	if _, err := io.ReadFull(r, mainkey); err != nil {
        return nil, nil, 0, nil, 0, 0, nil, 0, nil, err
    }
	key_des := binary.BigEndian.Uint64(mainkey[:8])
    if _, err := io.CopyN(io.Discard, r, 32+64); err != nil {
        return nil, nil, 0, nil, 0, 0, nil, 0, nil, err
    }

    // typeID
    typeID, err := r.ReadByte()
    if err != nil {
        return nil, nil, 0, nil, 0, 0, nil, 0, nil, err
    }

    // pointLen
    pointLen, err := r.ReadByte()
    if err != nil {
        return nil, nil, 0, nil, 0, 0, nil, 0, nil, err
    }
    if pointLen > maxPointLen {
        return nil, nil, 0, nil, 0, 0, nil, 0, nil, errors.New("point too long")
    }

    // tag
    tagBuf := make([]byte, 2)
    if _, err := io.ReadFull(r, tagBuf); err != nil {
        return nil, nil, 0, nil, 0, 0, nil, 0, nil, err
    }
    tag := binary.BigEndian.Uint16(tagBuf)

    // compress
    cp, err := r.ReadByte()
    if err != nil {
        return nil, nil, 0, nil, 0, 0, nil, 0, nil, err
    }
    if cp != 0 {
        return nil, nil, 0, nil, 0, 0, nil, 0, nil, errors.New("unsupported compression")
    }

    // domain
    domain := make([]byte, domainLen)
    if _, err := io.ReadFull(r, domain); err != nil {
        return nil, nil, 0, nil, 0, 0, nil, 0, nil, err
    }

    // pointTo
	var pointTo []byte
	if pointLen > 0 {
    pointTo = make([]byte, pointLen)
    if _, err := io.ReadFull(r, pointTo); err != nil {
        return nil, nil, 0, nil, 0, 0, nil, 0, nil, err
    }
	}

    // text
    txt := make([]byte, length)
    if _, err := io.ReadFull(r, txt); err != nil {
        return nil, nil, 0, nil, 0, 0, nil, 0, nil, err
    }
	
	thash := make([]byte, 32)
	if _, err := io.ReadFull(r, thash); err != nil {
        return nil, nil, 0, nil, 0, 0, nil, 0, nil, err
    }
	var point_To_root []byte
	
	if len(pointTo)>32{
		point_To_root=pointTo[32:len(pointTo)]
		pointTo=pointTo[:32]
	}
	
    return txt, domain, timestamp, pointTo,typeID,key_des,thash,tag,point_To_root, nil
}