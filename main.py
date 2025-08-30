import streamlit as st
from network_realtime_analyzer import RealTimeNetworkAnalyzer
import time  # Import time module for sleep

def main():
    st.title("Network Traffic Anomaly Detection")
    # Initialize the RealTimeNetworkAnalyzer
    analyzer = RealTimeNetworkAnalyzer()

    # Initialize Streamlit session state to track whether the analysis is running and store logs
    if 'analysis_running' not in st.session_state:
        st.session_state.analysis_running = False  # Default state is stopped
        st.session_state.logs = []  # Initialize an empty list to store logs
        st.session_state.anomalies = []  # Initialize an empty list to store detected anomalies

    # Button to trigger the custom anomaly for testing
    if st.button('Trigger Custom Anomaly'):
        analyzer.trigger_custom_anomaly()
        st.success('Custom anomaly triggered for testing.')

    # Button to reset custom anomaly
    if st.button('Reset Custom Anomaly'):
        analyzer.reset_custom_anomaly()
        st.success('Custom anomaly reset.')

    # Start and stop buttons for real-time network analysis
    if st.session_state.analysis_running:
        stop_button = st.button('Stop Real-Time Analysis')
        if stop_button:
            st.session_state.analysis_running = False
            st.write("Real-time network traffic analysis stopped.")
            
            # Display logs and flagged anomalies after stopping the analysis
            st.write("Logs of the last session:")
            for log in st.session_state.logs:
                st.write(log)
            
            st.write("Flagged Anomalies Detected:")
            for anomaly in st.session_state.anomalies:
                st.json(anomaly)
    else:
        start_button = st.button('Start Real-Time Analysis')
        if start_button:
            st.session_state.analysis_running = True
            st.write("Starting real-time network traffic analysis...")

    # Real-time network traffic analysis loop
    if st.session_state.analysis_running:
        while st.session_state.analysis_running:
            # Get anomalies detected using clustering method
            anomalies = analyzer.detect_anomalies()

            # If anomalies are detected, store them in the session state
            if anomalies:
                st.session_state.anomalies.append(anomalies)
                st.write("Critical Anomaly Detected!")
                st.json(anomalies)
            else:
                st.write("No Critical Anomalies Detected")

            # Display captured traffic data and store it in the session state
            captured_traffic = analyzer.packet_data[-10:]  # Show the last 10 packets
            st.session_state.logs.extend(captured_traffic)
            st.write("Captured Traffic:")
            st.json(captured_traffic)

            # Simulate delay between traffic captures (for testing purposes)
            st.write("Waiting for the next analysis cycle...")
            time.sleep(2)  # Adjust the sleep time as necessary

        st.write("Real-time network traffic analysis has stopped.")

if __name__ == "__main__":
    main()
