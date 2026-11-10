"""Independent Bell-state experiment. Never used as a payment security factor."""
import argparse
from qiskit import QuantumCircuit
from qiskit.quantum_info import Statevector

def circuit():
    qc = QuantumCircuit(2)
    qc.h(0)
    qc.cx(0, 1)
    return qc

def simulate():
    return dict(Statevector.from_instruction(circuit()).sample_counts(1024))

def hardware(backend_name):
    # Use only the user's normally configured IBM account. No embedded tokens.
    from qiskit_ibm_runtime import QiskitRuntimeService, SamplerV2
    from qiskit.transpiler.preset_passmanagers import generate_preset_pass_manager
    service = QiskitRuntimeService()
    backend = service.backend(backend_name)
    qc = circuit()
    qc.measure_all()
    isa = generate_preset_pass_manager(backend=backend, optimization_level=1).run(qc)
    job = SamplerV2(mode=backend).run([isa], shots=1024)
    print('Actual cloud job submitted. Job ID:', job.job_id())
    print(job.result()[0].data.meas.get_counts())

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--hardware', metavar='BACKEND_NAME')
    parser.add_argument('--accept-cloud-usage', action='store_true')
    args = parser.parse_args()
    if args.hardware:
        if not args.accept_cloud_usage:
            parser.error('Cloud use may consume quota or incur charges. Add --accept-cloud-usage to explicitly submit.')
        hardware(args.hardware)
    else:
        print('LOCAL SIMULATOR, NOT QUANTUM HARDWARE:', simulate())
