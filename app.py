import pandas as pd
import plotly.express as px
import streamlit as st
import threading
import time
from scapy.all import sniff
from network_monitor import get_dataframe, process_packet

def create_visualizations(df):
    """Create all dashboard visualizations"""
    if not df.empty:
        # Protocol distribution
        protocol_counts = df['protocol'].value_counts()
        fig_protocol = px.pie(
            values=protocol_counts.values,
            names=protocol_counts.index,
            title="Protocol Distribution"
        )
        st.plotly_chart(fig_protocol, use_container_width=True)

        # Packets timeline
        df['timestamp'] = pd.to_datetime(df['timestamp'])
        df_grouped = df.groupby(df['timestamp'].dt.floor('S')).size()
        fig_timeline = px.line(
            x=df_grouped.index,
            y=df_grouped.values,
            title="Packets per Second"
        )
        st.plotly_chart(fig_timeline, use_container_width=True)

        # Top source IPs
        top_sources = df['source'].value_counts().head(10)
        fig_sources = px.bar(
            x=top_sources.index,
            y=top_sources.values,
            title="Top Source IP Addresses"
        )
        st.plotly_chart(fig_sources, use_container_width=True)

def start_packet_capture():
    """Start packet capture in a separate thread"""
    def capture_packets():
        sniff(prn=process_packet, store=False)

    capture_thread = threading.Thread(target=capture_packets, daemon=True)
    capture_thread.start()
    return capture_thread

def main():
    """Main function to run the dashboard"""
    st.set_page_config(page_title="Network Traffic Analysis", layout="wide")
    st.title("Real-time Network Traffic Analysis")

    # Initialize packet capture in session state
    if 'capture_thread' not in st.session_state:
        st.session_state.capture_thread = start_packet_capture()
        st.session_state.start_time = time.time()

    # Create dashboard layout
    col1, col2 = st.columns(2)

    # Get current data
    df = get_dataframe()

    # Display metrics
    with col1:
        st.metric("Total Packets", len(df))
    with col2:
        duration = time.time() - st.session_state.start_time
        st.metric("Capture Duration", f"{duration:.2f}s")

    # Display visualizations
    create_visualizations(df)

    # Display recent packets
    st.subheader("Recent Packets")
    if not df.empty:
        st.dataframe(
            df.tail(10)[['timestamp', 'source', 'destination', 'protocol', 'size']],
            use_container_width=True
        )

    # Add refresh button
    if st.button('Refresh Data'):
        st.rerun()

    # Auto refresh
    time.sleep(2)
    st.rerun()

if __name__ == "__main__":
    main()