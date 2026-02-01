(function () {
    function initPasswordToggles(scope) {
        var root = scope || document;
        var toggles = root.querySelectorAll('[data-toggle="password"]');

        toggles.forEach(function (toggle) {
            toggle.addEventListener("click", function () {
                var targetId = toggle.getAttribute("data-target");
                var input = targetId ? document.getElementById(targetId) : null;
                if (!input) {
                    return;
                }

                var isHidden = input.type === "password";
                input.type = isHidden ? "text" : "password";
                toggle.setAttribute("aria-label", isHidden ? "Hide password" : "Show password");
            });
        });
    }

    if (document.readyState === "loading") {
        document.addEventListener("DOMContentLoaded", function () {
            initPasswordToggles(document);
        });
    } else {
        initPasswordToggles(document);
    }
})();
