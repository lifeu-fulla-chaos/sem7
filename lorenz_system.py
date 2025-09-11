import numpy as np # type: ignore
from scipy.integrate import solve_ivp # type: ignore


class LorenzParameters:
    def __init__(self, sigma, rho, beta):
        self.sigma = sigma
        self.rho = rho
        self.beta = beta


class LorenzSystem:
    def __init__(self, params: LorenzParameters, dt=0.01, initial_state=[1.0, 1.0, 1.0]):
        self.params = params
        self.dt = float(dt)
        self.initial_state = np.array(initial_state, dtype=float)
        self.state_history = None
        self.t = 0.0

    def lorenz_equations(self, t, state):
        x, y, z = state
        dx = self.params.sigma * (y - x)
        dy = x * (self.params.rho - z) - y
        dz = x * y - self.params.beta * z
        return [dx, dy, dz]

    def run_steps(self, steps: int, return_traj: bool = False):
        t_span = (self.t, self.t + self.dt * steps)
        t_eval = np.linspace(*t_span, steps)

        solution = solve_ivp(
            fun=self.lorenz_equations,
            t_span=t_span,
            y0=self.initial_state,
            t_eval=t_eval,
            method="RK45",
            rtol=1e-9,
            atol=1e-9,
        )
        self.state_history = solution.y.T
        self.initial_state = self.state_history[-1]
        self.t += (steps * self.dt)
        if return_traj:
            return self.state_history
        return None

    # -------- Slave dyn + backstepping --------
    def backstepping_control(self, x_master: np.ndarray, y_slave: np.ndarray, k: float = 5.0):
        x = np.asarray(x_master, dtype=float)
        y = np.asarray(y_slave, dtype=float)
        e = y - x

        u1 = -self.params.sigma * ((y[1] - y[0]) - (x[1] - x[0])) + e[1]
        u2 = -self.params.rho * (y[0] - x[0]) + (y[1] - x[1]) + (y[0] * y[2]) - (x[0] * x[2]) + e[2]
        u3 = (-y[0] * y[1]) + (x[0] * x[1]) + self.params.beta * (y[2] - x[2]) \
             - ((3 + 2 * k) * e[0]) - ((5 + 2 * k) * e[1]) - ((3 + k) * e[2])

        return np.array([u1, u2, u3], dtype=float), e


    