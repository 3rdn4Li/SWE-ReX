import logging
import shlex
import subprocess
import time
import uuid
from typing import Any

from typing_extensions import Self

from swerex import PACKAGE_NAME, REMOTE_EXECUTABLE_NAME
from swerex.deployment.abstract import AbstractDeployment
from swerex.deployment.config import DockerDeploymentConfig
from swerex.deployment.hooks.abstract import CombinedDeploymentHook, DeploymentHook
from swerex.exceptions import DeploymentNotStartedError, DockerPullError
from swerex.runtime.abstract import IsAliveResponse
from swerex.runtime.config import RemoteRuntimeConfig
from swerex.runtime.remote import RemoteRuntime
from swerex.utils.free_port import find_free_port
from swerex.utils.log import get_logger
from swerex.utils.wait import _wait_until_alive

__all__ = ["DockerDeployment", "DockerDeploymentConfig"]


def _is_image_available(image: str) -> bool:
    try:
        subprocess.check_call(["docker", "inspect", image], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        return True
    except subprocess.CalledProcessError:
        return False


def _pull_image(image: str) -> bytes:
    try:
        return subprocess.check_output(["docker", "pull", image], stderr=subprocess.PIPE)
    except subprocess.CalledProcessError as e:
        # e.stderr contains the error message as bytes
        raise subprocess.CalledProcessError(e.returncode, e.cmd, e.output, e.stderr) from None


def _remove_image(image: str) -> bytes:
    return subprocess.check_output(["docker", "rmi", image], timeout=30)


class DockerDeployment(AbstractDeployment):
    def __init__(
        self,
        *,
        logger: logging.Logger | None = None,
        **kwargs: Any,
    ):
        """Deployment to local docker image.

        Args:
            **kwargs: Keyword arguments (see `DockerDeploymentConfig` for details).
        """
        self._config = DockerDeploymentConfig(**kwargs)
        self._runtime: RemoteRuntime | None = None
        self._container_process = None
        self._container_name = None
        self.logger = logger or get_logger("rex-deploy")
        self._runtime_timeout = 0.15
        self._hooks = CombinedDeploymentHook()

    def add_hook(self, hook: DeploymentHook):
        self._hooks.add_hook(hook)

    @classmethod
    def from_config(cls, config: DockerDeploymentConfig) -> Self:
        return cls(**config.model_dump())

    def _get_container_name(self) -> str:
        """Returns a unique container name based on the image name."""
        image_name_sanitized = "".join(c for c in self._config.image if c.isalnum() or c in "-_.")
        return f"{image_name_sanitized}-{uuid.uuid4()}"

    @property
    def container_name(self) -> str | None:
        return self._container_name

    async def is_alive(self, *, timeout: float | None = None) -> IsAliveResponse:
        """Checks if the runtime is alive. The return value can be
        tested with bool().

        Raises:
            DeploymentNotStartedError: If the deployment was not started.
        """
        if self._runtime is None:
            msg = "Runtime not started"
            raise RuntimeError(msg)
        if self._container_process is None:
            msg = "Container process not started"
            raise RuntimeError(msg)
        if self._container_process.poll() is not None:
            msg = "Container process terminated."
            output = "stdout:\n" + self._container_process.stdout.read().decode()  # type: ignore
            output += "\nstderr:\n" + self._container_process.stderr.read().decode()  # type: ignore
            msg += "\n" + output
            raise RuntimeError(msg)
        return await self._runtime.is_alive(timeout=timeout)

    async def _wait_until_alive(self, timeout: float = 10.0):
        try:
            return await _wait_until_alive(self.is_alive, timeout=timeout, function_timeout=self._runtime_timeout)
        except TimeoutError as e:
            self.logger.error("Runtime did not start within timeout. Here's the output from the container process.")
            self.logger.error(self._container_process.stdout.read().decode())  # type: ignore
            self.logger.error(self._container_process.stderr.read().decode())  # type: ignore
            assert self._container_process is not None
            await self.stop()
            raise e

    def _get_token(self) -> str:
        return str(uuid.uuid4())

    def _get_swerex_start_cmd(self, token: str) -> list[str]:
        rex_args = f"--auth-token {token}"
        if self._config.python_standalone_dir:
            cmd = f"{self._config.python_standalone_dir}/python3.11/bin/{REMOTE_EXECUTABLE_NAME} {rex_args}"
        else:
            # Fallback chain when swerex-remote is not available in the container
            # Note: SWE-ReX requires Python 3.10+, we will upgrade Python if needed
            
            # 1. Ensure python3 and basic tools exist
            ensure_python = "command -v python3 >/dev/null 2>&1 || (apt-get update && apt-get install -y python3)"
            ensure_tools = "apt-get update && apt-get install -y software-properties-common curl"
            
            # 2. Check if Python upgrade is needed and upgrade to 3.10 if necessary
            check_python_version = "python3 -c 'import sys; exit(0 if sys.version_info >= (3, 10) else 1)' 2>/dev/null"
            upgrade_python = (
                "echo 'Python < 3.10 detected, upgrading to Python 3.10...' && "
                "add-apt-repository ppa:deadsnakes/ppa -y && "
                "apt-get update && "
                "apt-get install -y python3.10 python3.10-venv python3.10-dev python3.10-distutils && "
                "rm -f /usr/bin/python3 && ln -s /usr/bin/python3.10 /usr/bin/python3 && "
                "([ -f /usr/local/bin/python3 ] && (rm -f /usr/local/bin/python3 && ln -s /usr/bin/python3.10 /usr/local/bin/python3) || true) && "
                "curl -sS https://bootstrap.pypa.io/get-pip.py -o get-pip.py && python3 get-pip.py && rm -f get-pip.py"
            )
            
            # 3. Final Python version check (must be 3.10+ after upgrade)
            final_version_check = "python3 -c 'import sys; exit(0 if sys.version_info >= (3, 10) else 1)' 2>/dev/null"
            version_error_msg = "echo 'ERROR: Failed to upgrade Python to 3.10+. Current version:' && python3 --version && exit 1"
            
            # 4. Install and use pipx (only method, no pip fallback)
            install_pipx = "python3 -m pip install --user pipx"
            run_swerex = f"python3 -m pipx run {PACKAGE_NAME} {rex_args}"
            
            cmd = (
                f"{REMOTE_EXECUTABLE_NAME} {rex_args} || "
                f"(({ensure_python} && {ensure_tools} && "
                f"({check_python_version} || {upgrade_python}) && "
                f"{final_version_check} && {install_pipx} && {run_swerex}) || {version_error_msg})"
            )
        # Need to wrap with /bin/sh -c to avoid having '&&' interpreted by the parent shell
        return [
            "/bin/sh",
            # "-l",
            "-c",
            cmd,
        ]

    def _pull_image(self) -> None:
        if self._config.pull == "never":
            return
        if self._config.pull == "missing" and _is_image_available(self._config.image):
            return
        self.logger.info(f"Pulling image {self._config.image!r}")
        self._hooks.on_custom_step("Pulling docker image")
        try:
            _pull_image(self._config.image)
        except subprocess.CalledProcessError as e:
            msg = f"Failed to pull image {self._config.image}. "
            msg += f"Error: {e.stderr.decode()}"
            msg += f"Output: {e.output.decode()}"
            raise DockerPullError(msg) from e

    @property
    def glibc_dockerfile(self) -> str:
        # will only work with glibc-based systems
        if self._config.platform:
            platform_arg = f"--platform={self._config.platform}"
        else:
            platform_arg = ""
        return (
            "ARG BASE_IMAGE\n\n"
            # Build stage for standalone Python
            f"FROM {platform_arg} python:3.11-slim AS builder\n"
            # Install build dependencies
            "RUN apt-get update && apt-get install -y \\\n"
            "    wget \\\n"
            "    gcc \\\n"
            "    make \\\n"
            "    zlib1g-dev \\\n"
            "    libssl-dev \\\n"
            "    && rm -rf /var/lib/apt/lists/*\n\n"
            # Download and compile Python as standalone
            "WORKDIR /build\n"
            "RUN wget https://www.python.org/ftp/python/3.11.8/Python-3.11.8.tgz \\\n"
            "    && tar xzf Python-3.11.8.tgz\n"
            "WORKDIR /build/Python-3.11.8\n"
            "RUN ./configure \\\n"
            "    --prefix=/root/python3.11 \\\n"
            "    --enable-shared \\\n"
            "    LDFLAGS='-Wl,-rpath=/root/python3.11/lib' && \\\n"
            "    make -j$(nproc) && \\\n"
            "    make install && \\\n"
            "    ldconfig\n\n"
            # Production stage
            f"FROM {platform_arg} $BASE_IMAGE\n"
            # Ensure we have the required runtime libraries
            "RUN apt-get update && apt-get install -y \\\n"
            "    libc6 \\\n"
            "    && rm -rf /var/lib/apt/lists/*\n"
            # Copy the standalone Python installation
            f"COPY --from=builder /root/python3.11 {self._config.python_standalone_dir}/python3.11\n"
            f"ENV LD_LIBRARY_PATH={self._config.python_standalone_dir}/python3.11/lib:${{LD_LIBRARY_PATH:-}}\n"
            # Verify installation
            f"RUN {self._config.python_standalone_dir}/python3.11/bin/python3 --version\n"
            # Install swe-rex using the standalone Python
            f"RUN /root/python3.11/bin/pip3 install --no-cache-dir {PACKAGE_NAME}\n\n"
            f"RUN ln -s /root/python3.11/bin/{REMOTE_EXECUTABLE_NAME} /usr/local/bin/{REMOTE_EXECUTABLE_NAME}\n\n"
            f"RUN {REMOTE_EXECUTABLE_NAME} --version\n"
        )

    def _build_image(self) -> str:
        """Builds image, returns image ID."""
        self.logger.info(
            f"Building image {self._config.image} to install a standalone python to {self._config.python_standalone_dir}. "
            "This might take a while (but you only have to do it once). To skip this step, set `python_standalone_dir` to None."
        )
        dockerfile = self.glibc_dockerfile
        platform_arg = []
        if self._config.platform:
            platform_arg = ["--platform", self._config.platform]
        build_cmd = [
            "docker",
            "build",
            "-q",
            *platform_arg,
            "--build-arg",
            f"BASE_IMAGE={self._config.image}",
            "-",
        ]
        image_id = (
            subprocess.check_output(
                build_cmd,
                input=dockerfile.encode(),
            )
            .decode()
            .strip()
        )
        if not image_id.startswith("sha256:"):
            msg = f"Failed to build image. Image ID is not a SHA256: {image_id}"
            raise RuntimeError(msg)
        return image_id

    async def start(self):
        """Starts the runtime."""
        self._pull_image()
        if self._config.python_standalone_dir:
            image_id = self._build_image()
        else:
            image_id = self._config.image
        if self._config.port is None:
            self._config.port = find_free_port()
        assert self._container_name is None
        self._container_name = self._get_container_name()
        token = self._get_token()
        platform_arg = []
        if self._config.platform is not None:
            platform_arg = ["--platform", self._config.platform]
        rm_arg = []
        if self._config.remove_container:
            rm_arg = ["--rm"]
        cmds = [
            "docker",
            "run",
            *rm_arg,
            "-p",
            f"{self._config.port}:8000",
            *platform_arg,
            *self._config.docker_args,
            "--name",
            self._container_name,
            image_id,
            *self._get_swerex_start_cmd(token),
        ]
        cmd_str = shlex.join(cmds)
        self.logger.info(
            f"Starting container {self._container_name} with image {self._config.image} serving on port {self._config.port}"
        )
        self.logger.debug(f"Command: {cmd_str!r}")
        # shell=True required for && etc.
        self._container_process = subprocess.Popen(cmds, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        self._hooks.on_custom_step("Starting runtime")
        self.logger.info(f"Starting runtime at {self._config.port}")
        self._runtime = RemoteRuntime.from_config(
            RemoteRuntimeConfig(port=self._config.port, timeout=self._runtime_timeout, auth_token=token)
        )
        t0 = time.time()
        await self._wait_until_alive(timeout=self._config.startup_timeout)
        self.logger.info(f"Runtime started in {time.time() - t0:.2f}s")

    async def stop(self):
        """Stops the runtime."""
        if hasattr(self, '_runtime') and self._runtime is not None:
            await self._runtime.close()
            self._runtime = None

        if hasattr(self, '_container_process') and self._container_process is not None:
            try:
                if hasattr(self, '_container_name') and self._container_name:
                    subprocess.check_call(
                        ["docker", "kill", self._container_name],  # type: ignore
                        stdout=subprocess.DEVNULL,
                        stderr=subprocess.DEVNULL,
                        timeout=10,
                    )
            except (subprocess.CalledProcessError, subprocess.TimeoutExpired) as e:
                container_name = getattr(self, '_container_name', 'unknown')
                self.logger.warning(
                    f"Failed to kill container {container_name}: {e}. Will try harder.", exc_info=False
                )
            for _ in range(3):
                self._container_process.kill()
                try:
                    self._container_process.wait(timeout=5)
                    break
                except subprocess.TimeoutExpired:
                    continue
            else:
                container_name = getattr(self, '_container_name', 'unknown')
                self.logger.warning(f"Failed to kill container {container_name} with SIGKILL")

            self._container_process = None
            if hasattr(self, '_container_name'):
                self._container_name = None

        if hasattr(self, '_config') and self._config and getattr(self._config, 'remove_images', False):
            image_name = getattr(self._config, 'image', None)
            if image_name and _is_image_available(image_name):
                self.logger.info(f"Removing image {image_name}")
                try:
                    _remove_image(image_name)
                except subprocess.CalledProcessError:
                    self.logger.error(f"Failed to remove image {image_name}", exc_info=True)

    @property
    def runtime(self) -> RemoteRuntime:
        """Returns the runtime if running.

        Raises:
            DeploymentNotStartedError: If the deployment was not started.
        """
        if not hasattr(self, '_runtime') or self._runtime is None:
            raise DeploymentNotStartedError()
        return self._runtime
