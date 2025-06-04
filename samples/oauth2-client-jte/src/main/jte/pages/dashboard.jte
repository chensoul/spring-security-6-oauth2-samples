@import java.util.Map
@import com.chensoul.jte.CsrfHiddenInput

@param String userName = ""
@param String clientName = ""
@param Map<String, Object> userAttributes = null
@param CsrfHiddenInput csrfHiddenInput

@template.layout.default(
content = @`
    <div class="min-h-screen bg-gray-100">
        <nav class="bg-white shadow-sm">
            <div class="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
                <div class="flex justify-between h-16">
                    <div class="flex items-center">
                        <h1 class="text-xl font-semibold">Dashboard</h1>
                    </div>
                    <div class="flex items-center space-x-4">
                        <span class="text-gray-700">Welcome, ${userName}</span>
                        <form action="/logout" method="post">
                            ${csrfHiddenInput}
                            <button type="submit"
                                    class="px-4 py-2 bg-indigo-600 text-white rounded-md hover:bg-indigo-700">
                                Logout
                            </button>
                        </form>
                    </div>
                </div>
            </div>
        </nav>
        <main class="max-w-7xl mx-auto py-6 sm:px-6 lg:px-8">
            <div class="px-4 py-6 sm:px-0">
                <div class="bg-white shadow rounded-lg p-6">
                    <h2 class="text-2xl font-semibold text-gray-800 mb-4">OAuth 2.0 Login with Spring Security</h2>
                    <div>
                        You are successfully logged in <span style="font-weight:bold">${userName}</span>
                        via the OAuth 2.0 Client <span style="font-weight:bold">${clientName}</span>
                    </div>
                    <div>&nbsp;</div>
                    <div class="space-y-4">
                        <div>
                            <p class="text-sm font-medium text-gray-500">User Attributes</p>
                        </div>
                        @if(userAttributes != null && !userAttributes.isEmpty())
                            <div>
                                <div class="mt-1 flex-wrap gap-2">
                                    @for(String key : userAttributes.keySet())
                                        <div class="text-sm font-medium text-gray-500 pt-1 pb-1">${key}
                                            : ${userAttributes.get(key).toString()}</div>
                                    @endfor
                                </div>
                            </div>
                        @endif
                    </div>
                </div>
            </div>
        </main>
    </div>
`)