package skein

import (
    "os"
    )
type SkeinMac struct {
    skein *Skein
    stateSave []uint64
}

func NewMac(stateSize, outputSize int, key []byte) (s *SkeinMac, err os.Error) {
    s = new(SkeinMac)
    s.skein, err = NewExtended(stateSize, outputSize, 0, key)
    if err != nil {
        return nil, err
    }
    s.stateSave = make([]uint64, s.skein.cipherStateWords)
    copy(s.stateSave, s.skein.state)
    return s, nil
}

func (s *SkeinMac) Update(input []byte) {
    s.skein.Update(input)
}

func (s *SkeinMac) UpdateBits(input []byte, length int) os.Error {
    return s.skein.UpdateBits(input, length)
}

func (s *SkeinMac) DoFinal() []byte{
    ret := s.skein.DoFinal()
    s.Reset()
    return ret
}

func (s *SkeinMac) Reset() {
    copy(s.skein.state, s.stateSave)
}
