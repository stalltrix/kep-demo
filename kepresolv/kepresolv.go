package kepresolv

import (
    "bytes"
    "encoding/binary"
	"errors"
	"io"
)

type Kdata struct {
	Atxt  []byte
	Adomain []byte
	Atimestamp  int64
	Apoint_to []byte
	Aperm byte
	Akey_des uint64
	Athash []byte
	Atag uint16
	Aroot []byte
	Atag2 uint16
}

func bytesToInt64(b []byte) int64 {
    if len(b) != 5 {
        return 0
    }
    var t uint64
    t |= uint64(b[0]) << 32
    t |= uint64(b[1]) << 24
    t |= uint64(b[2]) << 16
    t |= uint64(b[3]) << 8
    t |= uint64(b[4])
    return int64(t)
}

func Resolv(data []byte) (Kdata, error) {
    var dat Kdata
	r := bytes.NewReader(data)

    const (
        maxDomainLen = 250
        maxPointLen  = 160
        maxTextLen   = 65535
    )

    // version
    version, err := r.ReadByte()
    if err != nil {
        return dat, err
    }
    if version != 1 {
        return dat, errors.New("unsupported version")
    }

    // hashType
    _, err = r.ReadByte()
    if err != nil {
        return dat, err
    }

    // domainLen
    domainLen, err := r.ReadByte()
    if err != nil {
        return dat, err
    }
    if domainLen == 0 || domainLen > maxDomainLen {
        return dat, errors.New("invalid domain length")
    }

    // timestamp
    timestampBytes := make([]byte, 5)
    if _, err := io.ReadFull(r, timestampBytes); err != nil {
        return dat, err
    }
    timestamp := bytesToInt64(timestampBytes)

    // length
    lg := make([]byte, 2)
    if _, err := io.ReadFull(r, lg); err != nil {
        return dat, err
    }
    length := binary.BigEndian.Uint16(lg)
    if length > maxTextLen {
        return dat, errors.New("text too large")
    }

    // keys
	mainkey := make([]byte, 32)
	if _, err := io.ReadFull(r, mainkey); err != nil {
        return dat, err
    }
	key_des := binary.BigEndian.Uint64(mainkey[:8])
    if _, err := io.CopyN(io.Discard, r, 32+64); err != nil {
        return dat, err
    }

    // typeID
    typeID, err := r.ReadByte()
    if err != nil {
        return dat, err
    }

    // pointLen
    pointLen, err := r.ReadByte()
    if err != nil {
        return dat, err
    }
    if pointLen > maxPointLen {
        return dat, errors.New("point too long")
    }

    // tag
    tagBuf := make([]byte, 2)
    if _, err := io.ReadFull(r, tagBuf); err != nil {
        return dat, err
    }
    tag := binary.BigEndian.Uint16(tagBuf)

    // compress
    cp, err := r.ReadByte()
    if err != nil {
        return dat, err
    }
    if cp != 0 {
        return dat, errors.New("unsupported compression")
    }

    // domain
    domain := make([]byte, domainLen)
    if _, err := io.ReadFull(r, domain); err != nil {
        return dat, err
    }

    // pointTo
	var pointTo []byte
	if pointLen > 0 {
    pointTo = make([]byte, pointLen)
    if _, err := io.ReadFull(r, pointTo); err != nil {
        return dat, err
    }
	}

    // text
    txt := make([]byte, length)
    if _, err := io.ReadFull(r, txt); err != nil {
        return dat, err
    }
	
	thash := make([]byte, 32)
	if _, err := io.ReadFull(r, thash); err != nil {
        return dat, err
    }
	var point_To_root []byte
	
	if len(pointTo)>32{
		point_To_root=pointTo[32:len(pointTo)]
		pointTo=pointTo[:32]
	}
	
	if _, err := io.CopyN(io.Discard, r, 64); err != nil {
        return dat, err
    }
	
	// tag2
    tag2Buf := make([]byte, 2)
    if _, err := io.ReadFull(r, tag2Buf); err != nil {
        return dat, err
    }
    tag2 := binary.BigEndian.Uint16(tag2Buf)
	
	dat.Atxt=txt
	dat.Adomain=domain
	dat.Atimestamp=timestamp
	dat.Apoint_to=pointTo
	dat.Aperm=typeID
	dat.Akey_des=key_des
	dat.Athash=thash
	dat.Atag=tag
	dat.Aroot=point_To_root
	dat.Atag2=tag2
    return dat,nil
}