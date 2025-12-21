// src/eui/backend/gui/qt/dashboard.qml

import QtQuick 2.15
import QtQuick.Controls 2.15
import QtQuick.Layouts 1.15

ApplicationWindow {
    id: root
    visible: true
    width: 1100
    height: 800
    title: "ETP-CORE // Qt Evolutionary Dashboard"
    color: "#0d0f18" // 背景色：深色极客风

    // --- 由 Rust 注入的后端对象 ---
    // Backend 对象拥有 node_id, bps_in, bps_out, sessions 等属性
    
    ColumnLayout {
        anchors.fill: parent
        anchors.margins: 20
        spacing: 15

        // 1. Header Area
        RowLayout {
            Text {
                text: "NODE // " + Backend.node_id
                font.pixelSize: 24
                font.bold: true
                color: "#00f2ff"
            }
            Item { Layout.fillWidth: true }
            Text {
                text: "Uptime: " + Backend.uptime
                color: "#565f89"
                font.family: "Monospace"
            }
        }

        // 2. Real-time Gauges
        RowLayout {
            spacing: 20
            Layout.preferredHeight: 150

            // Ingress Box
            Rectangle {
                Layout.fillWidth: true
                Layout.fillHeight: true
                color: "#161925"
                radius: 10
                border.color: "#9ece6a"
                border.width: 1
                ColumnLayout {
                    anchors.centerIn: parent
                    Text { text: "INGRESS"; color: "#9ece6a"; font.pixelSize: 12; Layout.alignment: Qt.AlignHCenter }
                    Text { text: Backend.bps_in; color: "white"; font.pixelSize: 32; font.bold: true; Layout.alignment: Qt.AlignHCenter }
                }
            }

            // Egress Box
            Rectangle {
                Layout.fillWidth: true
                Layout.fillHeight: true
                color: "#161925"
                radius: 10
                border.color: "#7dcfff"
                border.width: 1
                ColumnLayout {
                    anchors.centerIn: parent
                    Text { text: "EGRESS"; color: "#7dcfff"; font.pixelSize: 12; Layout.alignment: Qt.AlignHCenter }
                    Text { text: Backend.bps_out; color: "white"; font.pixelSize: 32; font.bold: true; Layout.alignment: Qt.AlignHCenter }
                }
            }
        }

        // 3. Session Table (ListView)
        Rectangle {
            Layout.fillWidth: true
            Layout.fillHeight: true
            color: "#16161e"
            radius: 8
            clip: true

            ListView {
                anchors.fill: parent
                model: Backend.sessions
                header: RowLayout {
                    width: parent.width; height: 30
                    Text { text: " IDENTITY"; color: "#565f89"; Layout.preferredWidth: 200 }
                    Text { text: " ADDRESS"; color: "#565f89"; Layout.preferredWidth: 250 }
                    Text { text: " RTT"; color: "#565f89"; Layout.preferredWidth: 80 }
                    Text { text: " FLAVOR"; color: "#565f89"; Layout.fillWidth: true }
                }
                delegate: ItemDelegate {
                    width: parent.width
                    contentItem: RowLayout {
                        Text { text: modelData.identity; color: "#c0caf5" }
                        Text { text: modelData.addr; color: "#7aa2f7" }
                        Text { text: modelData.rtt + "ms"; color: "#bb9af7" }
                        Text { text: modelData.flavor; color: "#565f89" }
                    }
                }
            }
        }

        // 4. Footer
        RowLayout {
            Button {
                text: "Trigger Global Rekey"
                onClicked: Backend.trigger_global_rekey()
            }
            Item { Layout.fillWidth: true }
            Button {
                text: "EMERGENCY SHUTDOWN"
                highlighted: true
                onClicked: Backend.shutdown_node()
            }
        }
    }
}