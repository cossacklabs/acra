package postgresql

import (
	"testing"
)

func Test_newPendingPackets(t *testing.T) {
	pendingPackets := newPendingPacketsList()
	if packet, err := pendingPackets.GetPendingPacket(&BindPacket{}); err != nil {
		t.Fatal(err)
	} else if packet != nil {
		t.Fatal("Packet should be nil")
	}

	if packet, err := pendingPackets.GetLastPending(&BindPacket{}); err != nil {
		t.Fatal(err)
	} else if packet != nil {
		t.Fatal("Packet should be nil")
	}

	if err := pendingPackets.Add(&BindPacket{portal: "portal1"}); err != nil {
		t.Fatal(err)
	}

	if packet, err := pendingPackets.GetPendingPacket(&BindPacket{}); err != nil {
		t.Fatal(err)
	} else if packet == nil {
		t.Fatal("Packet should not be nil")
	} else if packet.(*BindPacket).portal != "portal1" {
		t.Fatal("Unexpected value")
	}

	if packet, err := pendingPackets.GetLastPending(&BindPacket{}); err != nil {
		t.Fatal(err)
	} else if packet == nil {
		t.Fatal("Packet should not be nil")
	} else if packet.(*BindPacket).portal != "portal1" {
		t.Fatal("Unexpected value")
	}

	if err := pendingPackets.Add(&BindPacket{portal: "portal2"}); err != nil {
		t.Fatal(err)
	}

	if packet, err := pendingPackets.GetPendingPacket(&BindPacket{}); err != nil {
		t.Fatal(err)
	} else if packet == nil {
		t.Fatal("Packet should not be nil")
	} else if packet.(*BindPacket).portal != "portal1" {
		t.Fatal("Unexpected value")
	}

	if packet, err := pendingPackets.GetLastPending(&BindPacket{}); err != nil {
		t.Fatal(err)
	} else if packet == nil {
		t.Fatal("Packet should not be nil")
	} else if packet.(*BindPacket).portal != "portal2" {
		t.Fatal("Unexpected value")
	}

	if err := pendingPackets.RemoveNextPendingPacket(&BindPacket{}); err != nil {
		t.Fatal(err)
	}
	if packet, err := pendingPackets.GetPendingPacket(&BindPacket{}); err != nil {
		t.Fatal(err)
	} else if packet == nil {
		t.Fatal("Packet should not be nil")
	} else if packet.(*BindPacket).portal != "portal2" {
		t.Fatal("Unexpected value")
	}

	if packet, err := pendingPackets.GetLastPending(&BindPacket{}); err != nil {
		t.Fatal(err)
	} else if packet == nil {
		t.Fatal("Packet should not be nil")
	} else if packet.(*BindPacket).portal != "portal2" {
		t.Fatal("Unexpected value")
	}

	if err := pendingPackets.RemoveAll(&BindPacket{}); err != nil {
		t.Fatal(err)
	}
	if packet, err := pendingPackets.GetPendingPacket(&BindPacket{}); err != nil {
		t.Fatal(err)
	} else if packet != nil {
		t.Fatal("Packet should be nil")
	}

	if packet, err := pendingPackets.GetLastPending(&BindPacket{}); err != nil {
		t.Fatal(err)
	} else if packet != nil {
		t.Fatal("Packet should be nil")
	}
}
